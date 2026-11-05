//! MiniMax 积分余额（`GET /minimax-cloud/api/v1/credit/details`）。
//!
//! ── 两个必须踩对的细节（都是网关侧实测出来的）───────────────────
//! 1. **必须显式传 `page_size`**：不传时上游只回 20 条，而余额要按包求和 ——
//!    同一账号 `total_count=31` 但 `details.len()=20`，求和直接少算。
//!    上限 100（`page_size=101` 上游 500），而 100 已覆盖「每天新增一个包、
//!    连续 100 天」的全部现实场景。
//! 2. **余额不是 `total_count`**：那是包**个数**。真实余额是逐包的
//!    `remaining_amount` 求和。曾经把 `total_count` 当余额，账号为 0 时
//!    `details` 缺失、`total_count` 也是 0，看起来「恰好对」——所以这个错误
//!    长期没被发现。
//!
//! `page` / `page_num` 实测无效（翻不动页），所以拿不到第 101 条之后的包；
//! 那种情况下把「已取到的条数 < total_count」如实标出来，不假装是全量。

use serde_json::{json, Value};

/// 单次请求最多取多少包（与上游上限一致）。
pub const PAGE_MAX: usize = 100;

/// 逐个包求和后的余额读数。
pub struct CreditSummary {
    /// 所有包的剩余额之和
    pub remaining: f64,
    /// 逐包明细（给「积分明细」弹层用）
    pub credits: Vec<Value>,
    /// 上游报的包总数（> 取到的条数 = 还有没取到的）
    pub total_count: i64,
}

fn number_of(value: Option<&Value>) -> f64 {
    match value {
        Some(Value::Number(number)) => number.as_f64().unwrap_or(0.0),
        // 上游把金额写成字符串（`"800.00"`）
        Some(Value::String(text)) => text.trim().parse::<f64>().unwrap_or(0.0),
        _ => 0.0,
    }
}

/// 解析 `credit/details` 的响应。
pub fn parse_credit_details(body: &Value) -> Result<CreditSummary, String> {
    // 业务错误在 `base_resp.status_code`（HTTP 仍是 200）
    if let Some(code) = body
        .pointer("/base_resp/status_code")
        .and_then(Value::as_i64)
    {
        if code != 0 {
            let message = body
                .pointer("/base_resp/status_msg")
                .and_then(Value::as_str)
                .unwrap_or("未知错误");
            return Err(format!("MiniMax 积分查询失败（{code}）：{message}"));
        }
    }
    let details = body
        .get("details")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let total_count = body.get("total_count").and_then(Value::as_i64).unwrap_or(0);
    let mut remaining = 0.0;
    let mut credits = Vec::new();
    for item in &details {
        let amount = number_of(
            item.get("remaining_amount")
                .or_else(|| item.get("remainingAmount")),
        );
        remaining += amount;
        credits.push(json!({
            "name": item.get("label").and_then(Value::as_str).unwrap_or("积分包"),
            "remain": amount,
            "total": number_of(item.get("total_amount").or_else(|| item.get("totalAmount"))),
            "used": number_of(item.get("used_amount").or_else(|| item.get("usedAmount"))),
            "expireAt": item.get("expire_at").or_else(|| item.get("expireAt")).cloned().unwrap_or(Value::Null),
        }));
    }
    Ok(CreditSummary {
        remaining,
        credits,
        total_count,
    })
}

/// 组装成网关能直接展示的 `UsageReport`。
///
/// ── 键名严格照抄插件的既有约定 ────────────────────────────────
/// `{unit, wallets[], subscription, raw, available}`（与 atomcode / loomy 同款）。
/// **不自造键名**：界面只认这一套，自造会让账号页余额列空白而探针全绿。
/// `credits[]` 是额外的逐包明细，只在申报了 `credit_detail` 能力位时被读。
///
/// `available` 只在**真的解析出逐包读数**时写：读不到时留空表示「没读懂这份
/// 响应」，而不是「余额为 0」—— 把空当成 0 会让限额判定把账号误判成欠费。
pub fn report_json(summary: &CreditSummary) -> Value {
    let wallets: Vec<Value> = summary
        .credits
        .iter()
        .map(|item| {
            json!({
                "type": "credit_package",
                "displayName": item.get("name").cloned().unwrap_or(json!("积分包")),
                "balance": item.get("remain").cloned().unwrap_or(json!(0)),
                "remaining": item.get("remain").cloned().unwrap_or(json!(0)),
                "limit": item.get("total").cloned().unwrap_or(Value::Null),
                "used": item.get("used").cloned().unwrap_or(json!(0)),
                "expireAt": item.get("expireAt").cloned().unwrap_or(Value::Null),
            })
        })
        .collect();
    let mut shaped = json!({
        "unit": "积分",
        "wallets": wallets,
        "credits": summary.credits,
        "subscription": { "status": "unknown" },
        // 上游翻不动页：取不全时如实标记，界面据此显示「部分覆盖」
        "truncated": summary.total_count > PAGE_MAX as i64,
        "totalCount": summary.total_count,
        "updatedAt": chrono::Utc::now().timestamp_millis(),
    });
    if let Some(object) = shaped.as_object_mut() {
        if !summary.credits.is_empty() {
            object.insert("available".to_string(), json!(summary.remaining));
        }
        object.insert("raw".to_string(), json!({ "totalCount": summary.total_count }));
    }
    shaped
}
