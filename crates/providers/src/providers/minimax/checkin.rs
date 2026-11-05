//! MiniMax 每日签到（`signin/status` + `signin/claim`）。
//!
//! ── 两个必须带对的东西 ──────────────────────────────────────────
//! 1. **`timezone_id` 必须带**（IANA 时区名）：签到按客户端上报的时区结算，
//!    不带或写错会被上游判成「今天还没到」或「invalid timezone_id」——
//!    **两者都是 HTTP 200**，只能靠 `base_resp.status_code` 分辨。
//! 2. **幂等判据是 `claim_result`**：`1` = 本次真领取、`2` = 今天已领过。
//!    把 `2` 当成失败会让「重复点签到」显示成红字错误；当成成功又会虚报一次
//!    领取。两种都要如实区分。
//!
//! 默认时区取 `Asia/Shanghai`（本机形态），可用环境变量
//! `MINIMAX_TIMEZONE` 覆盖 —— 插件里拿不到系统的 IANA 时区名（那要
//! `chrono-tz` 或平台 API），而签到时区错一小时就会跨日。

use serde_json::{json, Value};

/// `signin/status` 里「今天的状态」编码。
const STATUS_CLAIMED: i64 = 3;
const STATUS_CLAIMABLE: i64 = 2;

/// `signin/claim` 的结果编码。
const CLAIM_RESULT_CLAIMED: i64 = 1;
const CLAIM_RESULT_ALREADY: i64 = 2;

/// 签到用的时区名。
pub fn timezone_id() -> String {
    std::env::var("MINIMAX_TIMEZONE")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "Asia/Shanghai".to_string())
}

/// 业务错误（HTTP 200 + 非零 `base_resp.status_code`）。
fn business_error(body: &Value) -> Option<String> {
    let code = body.pointer("/base_resp/status_code").and_then(Value::as_i64)?;
    if code == 0 {
        return None;
    }
    let message = body
        .pointer("/base_resp/status_msg")
        .and_then(Value::as_str)
        .unwrap_or("未知错误");
    Some(format!("MiniMax 业务错误（{code}）：{message}"))
}

/// 有 `data` 对象就用它，否则用顶层（两个端点形状不同）。
fn unwrap_data(payload: &Value) -> Value {
    match payload.get("data") {
        Some(value) if value.is_object() => value.clone(),
        _ => payload.clone(),
    }
}

/// 状态查询的结论。
#[derive(Debug)]
pub struct CheckinStatus {
    pub claimed_today: bool,
    pub claimable: bool,
    /// 连续签到天数（上游给就给）
    pub streak: Option<u32>,
}

/// 解析 `signin/status`。
pub fn parse_status(body: &Value) -> Result<CheckinStatus, String> {
    if let Some(error) = business_error(body) {
        return Err(error);
    }
    let data = unwrap_data(body);
    let days = data
        .get("days")
        .or_else(|| data.get("list"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let claimed_today = days.iter().any(|day| {
        day.get("is_today").and_then(Value::as_bool) == Some(true)
            && day.get("status").and_then(Value::as_i64) == Some(STATUS_CLAIMED)
    });
    let claimable = days.iter().any(|day| {
        day.get("is_today").and_then(Value::as_bool) == Some(true)
            && day.get("status").and_then(Value::as_i64) == Some(STATUS_CLAIMABLE)
    });
    let streak = data
        .get("continue_days")
        .or_else(|| data.get("streak"))
        .or_else(|| data.get("continuous_days"))
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok());
    // ── 认不出这份响应就说认不出 ────────────────────────────────
    // 既没有逐日状态、也没有任何连续天数：这不是签到状态。以前这里直接落成
    // `claimed=false / claimable=false`，于是上游 401 的
    // `{"error":"invalid access token"}` 一路显示成「今天不在可签到的时间
    // 窗口内」—— 把鉴权失败讲成了业务结论，排查方向被完全带偏（实测两个从旧库
    // 桥接来的账号就是这样静默「变没得签」）。
    if days.is_empty() && streak.is_none() {
        let preview: String = body.to_string().chars().take(200).collect();
        return Err(format!(
            "签到状态响应无法解析（既无逐日状态也无连续天数）：{preview}"
        ));
    }
    Ok(CheckinStatus {
        claimed_today,
        claimable,
        streak,
    })
}

/// 领取结论。
pub enum ClaimOutcome {
    /// 本次真领到了
    Claimed { credit: Option<String> },
    /// 今天已经领过
    Already,
}

/// 解析 `signin/claim`。
pub fn parse_claim(body: &Value) -> Result<ClaimOutcome, String> {
    if let Some(error) = business_error(body) {
        return Err(error);
    }
    let data = unwrap_data(body);
    match data.get("claim_result").and_then(Value::as_i64) {
        Some(CLAIM_RESULT_CLAIMED) => {
            let credit = data
                .get("points")
                .or_else(|| data.get("credit"))
                .map(|value| match value {
                    Value::Number(number) => number.to_string(),
                    Value::String(text) => text.clone(),
                    other => other.to_string(),
                });
            Ok(ClaimOutcome::Claimed { credit })
        }
        Some(CLAIM_RESULT_ALREADY) => Ok(ClaimOutcome::Already),
        other => Err(format!(
            "签到响应缺少有效的 claim_result（收到 {other:?}）"
        )),
    }
}

/// 供日志用的摘要（不打整份响应）。
pub fn status_summary(status: &CheckinStatus) -> Value {
    json!({
        "claimedToday": status.claimed_today,
        "claimable": status.claimable,
        "streak": status.streak,
        "timezone": timezone_id(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// 401 的错误体不能变成「今天不在窗口内」。
    #[test]
    fn status_rejects_unrecognized_payload() {
        let error = parse_status(&json!({ "error": "invalid access token" })).unwrap_err();
        assert!(error.contains("无法解析"), "{error}");
        assert!(error.contains("invalid access token"), "{error}");
    }

    #[test]
    fn status_reads_today_entry_and_streak() {
        let status = parse_status(&json!({
            "data": { "days": [{ "is_today": true, "status": 2 }], "continue_days": 5 }
        }))
        .unwrap();
        assert!(status.claimable && !status.claimed_today);
        assert_eq!(status.streak, Some(5));
    }

    #[test]
    fn status_detects_claimed_today() {
        let status = parse_status(&json!({
            "data": { "list": [{ "is_today": true, "status": 3 }] }
        }))
        .unwrap();
        assert!(status.claimed_today && !status.claimable);
    }
}
