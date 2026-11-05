//! MiniMax 对话请求构造（Anthropic Messages 协议）。
//!
//! ── 为什么走 `UpstreamKind::Anthropic` ────────────────────────
//! 上游的推理端点 `/mavis/api/v1/llm/v1/messages` 说的就是 Anthropic Messages：
//! `system` 是顶层字段、内容块有 `tool_use` / `tool_result`、图片走
//! `source.type=base64`。网关侧已经有「Anthropic SSE → chat SSE」的翻译机，
//! 所以插件只需要：把 chat 体翻成 Anthropic 体 + 声明 `upstream: Anthropic`，
//! 其余的流翻译、usage 提取、纠错都在网关。
//!
//! ── 思考决策表（真机实测，逐条对齐参考实现）────────────────────
//! | 情形 | 请求体 |
//! |---|---|
//! | `off` / `none`（switchable）| `thinking:{type:'disabled'}` |
//! | `on`（switchable）| `thinking:{type:'adaptive'}` |
//! | 有档位 effort | `thinking:{type:'adaptive'}` + `output_config.effort` |
//! | M3 系（`ADAPTIVE_ONLY_PREFIX`）| `thinking:{type:'adaptive'}`（**必须**，否则 400） |
//! | 其余（M2.7 系）| **整个不发**（服务端默认 forced_on） |
//!
//! ⚠️ 两条硬约束：
//!   - M3 不发 `thinking` 时默认「不思考」（实测两轮各 0 字符），所以「开启
//!     思考」必须显式发 `adaptive`；
//!   - `forced_on` 的模型**绝不**发 `disabled` —— M3.1 会硬 400，M2.7 会被
//!     静默忽略（用户以为关掉了、实际没关）。

use serde_json::{json, Map, Value};

use super::product;

/// 构造一条发往上游的 Anthropic Messages 请求体。
///
/// `reasoning` 是网关解析出的思考档位（用户配置里那条值，可能为空）。
/// 翻译成上游字段是本模块的事 —— 网关只负责把用户的意图带过来。
pub fn build_messages_body(body: &Value, wire_model: &str, reasoning: &str) -> Result<Value, String> {
    let mut out = Map::new();
    out.insert("model".to_string(), Value::String(wire_model.to_string()));
    out.insert("stream".to_string(), Value::Bool(true));

    // ── system / messages ────────────────────────────────────
    // chat 体的 `system`（若有）原样搬；Anthropic 的 system 是**顶层字符串
    // 或内容块数组**，不是 messages 里的一个角色。
    if let Some(system) = body.get("system") {
        if !system.is_null() {
            out.insert("system".to_string(), system.clone());
        }
    }
    let messages = body
        .get("messages")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    // chat 方言里 role=system 的消息要提到顶层（Anthropic 不接受 system 角色）
    let mut system_parts: Vec<String> = Vec::new();
    let mut kept: Vec<Value> = Vec::new();
    for message in messages {
        let role = message.get("role").and_then(Value::as_str).unwrap_or("");
        if role == "system" {
            if let Some(text) = message.get("content").and_then(Value::as_str) {
                if !text.trim().is_empty() {
                    system_parts.push(text.to_string());
                }
            }
            continue;
        }
        kept.push(message);
    }
    if !system_parts.is_empty() {
        let joined = system_parts.join("\n\n");
        match out.get("system") {
            // 已有顶层 system：拼在一起，不丢任何一侧
            Some(Value::String(existing)) if !existing.trim().is_empty() => {
                out.insert(
                    "system".to_string(),
                    Value::String(format!("{existing}\n\n{joined}")),
                );
            }
            Some(Value::Null) | None => {
                out.insert("system".to_string(), Value::String(joined));
            }
            // 内容块数组形态：追加一个 text 块
            Some(Value::Array(items)) => {
                let mut items = items.clone();
                items.push(json!({ "type": "text", "text": joined }));
                out.insert("system".to_string(), Value::Array(items));
            }
            _ => {}
        }
    }
    out.insert("messages".to_string(), Value::Array(kept));

    // ── max_tokens（Anthropic 必填）──────────────────────────
    let max_tokens = body
        .get("max_tokens")
        .and_then(Value::as_i64)
        .filter(|value| *value > 0)
        // 缺省给 8192：Anthropic 协议要求这个字段，不给直接被上游 400
        .unwrap_or(8192);
    out.insert("max_tokens".to_string(), Value::from(max_tokens));

    // ── 采样参数：只搬上游认识的 ──────────────────────────────
    for key in ["temperature", "top_p", "top_k", "stop_sequences"] {
        if let Some(value) = body.get(key) {
            if !value.is_null() {
                out.insert(key.to_string(), value.clone());
            }
        }
    }
    // chat 的 `stop`（字符串或数组）→ Anthropic 的 `stop_sequences`（数组）
    if !out.contains_key("stop_sequences") {
        if let Some(stop) = body.get("stop") {
            match stop {
                Value::String(text) => {
                    out.insert("stop_sequences".to_string(), json!([text]));
                }
                Value::Array(items) => {
                    out.insert("stop_sequences".to_string(), Value::Array(items.clone()));
                }
                _ => {}
            }
        }
    }

    // ── 工具 ────────────────────────────────────────────────
    // chat 的 `{type:"function", function:{name,description,parameters}}`
    // → Anthropic 的 `{name, description, input_schema}`（**没有** type 包裹）
    if let Some(tools) = body.get("tools").and_then(Value::as_array) {
        let converted: Vec<Value> = tools
            .iter()
            .filter_map(|tool| {
                let function = tool.get("function")?;
                let name = function.get("name").and_then(Value::as_str)?;
                let mut entry = Map::new();
                entry.insert("name".to_string(), Value::String(name.to_string()));
                if let Some(description) = function.get("description").and_then(Value::as_str) {
                    entry.insert(
                        "description".to_string(),
                        Value::String(description.to_string()),
                    );
                }
                let schema = function
                    .get("parameters")
                    .cloned()
                    .unwrap_or_else(|| json!({ "type": "object", "properties": {} }));
                entry.insert("input_schema".to_string(), schema);
                Some(Value::Object(entry))
            })
            .collect();
        if !converted.is_empty() {
            out.insert("tools".to_string(), Value::Array(converted));
        }
    }

    // ── 思考档位（决策表见模块头）─────────────────────────────
    apply_reasoning(&mut out, wire_model, reasoning);

    Ok(Value::Object(out))
}

/// 按决策表写入思考字段。
fn apply_reasoning(out: &mut Map<String, Value>, wire_model: &str, reasoning: &str) {
    let level = reasoning.trim().to_ascii_lowercase();
    let off = matches!(level.as_str(), "" | "off" | "none" | "disabled" | "0" | "false");
    let adaptive_only = wire_model.starts_with(product::ADAPTIVE_ONLY_PREFIX);

    // M3 系：必须显式 adaptive，且**绝不**发 disabled
    if adaptive_only {
        out.insert("thinking".to_string(), json!({ "type": "adaptive" }));
        return;
    }

    if off {
        // 非 M3 的 switchable 模型：显式关闭是合法且必要的（否则服务端可能默认开）
        // 但 forced_on 的模型会被静默忽略 —— 那也好过不发（至少语义明确）
        out.insert("thinking".to_string(), json!({ "type": "disabled" }));
        return;
    }

    // 开启：adaptive；若档位是具体 effort，再带上 output_config
    out.insert("thinking".to_string(), json!({ "type": "adaptive" }));
    if matches!(level.as_str(), "low" | "medium" | "high" | "max" | "minimal") {
        out.insert("output_config".to_string(), json!({ "effort": level }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(value: Value) -> Value {
        build_messages_body(&value, "MiniMax-M2.7", "").unwrap()
    }

    #[test]
    fn system_role_messages_move_to_top_level() {
        let out = body(json!({
            "messages": [
                {"role": "system", "content": "be brief"},
                {"role": "user", "content": "hi"}
            ]
        }));
        assert_eq!(out["system"], json!("be brief"));
        assert_eq!(out["messages"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn m3_always_gets_adaptive_even_when_reasoning_is_off() {
        let out = build_messages_body(
            &json!({"messages": [{"role": "user", "content": "hi"}]}),
            "MiniMax-M3",
            "off",
        )
        .unwrap();
        assert_eq!(out["thinking"], json!({ "type": "adaptive" }));
    }

    #[test]
    fn max_tokens_defaults_when_absent() {
        let out = body(json!({"messages": [{"role": "user", "content": "hi"}]}));
        assert_eq!(out["max_tokens"], json!(8192));
    }

    #[test]
    fn chat_tools_convert_to_anthropic_shape() {
        let out = body(json!({
            "messages": [{"role": "user", "content": "hi"}],
            "tools": [{"type": "function", "function": {
                "name": "lookup", "description": "find", "parameters": {"type": "object"}
            }}]
        }));
        let tools = out["tools"].as_array().unwrap();
        assert_eq!(tools[0]["name"], json!("lookup"));
        assert!(tools[0].get("input_schema").is_some());
        assert!(tools[0].get("function").is_none());
    }

    #[test]
    fn stream_is_always_enabled() {
        assert_eq!(body(json!({"messages": []}))["stream"], json!(true));
    }
}
