//! MiniMax OAuth（设备码 + PKCE）与令牌续期。
//!
//! ── 上游形态（照网关侧实现移植）──────────────────────────────
//! ```text
//! POST {ACCOUNT_HOST}/oauth2/device/code
//!      {client_id, scope, audience, code_challenge, code_challenge_method:S256}
//! POST {ACCOUNT_HOST}/oauth2/token
//!      {grant_type: urn:ietf:params:oauth:grant-type:device_code,
//!       device_code, client_id, code_verifier}
//! POST {ACCOUNT_HOST}/oauth2/token
//!      {grant_type: refresh_token, refresh_token, client_id, scope, audience}
//! ```
//!
//! ── 轮询的两种失败形态都要认 ──────────────────────────────────
//! 实测（2026-11-06，`/oauth2/token` 未授权时）存在两种：
//!   · `HTTP 200 + status:"pending"`；
//!   · **标准 OAuth 的 `HTTP 400 + error:"authorization_pending"`** ——
//!     实测上游这一版回的就是这一种：
//!     `{"error":"authorization_pending","error_description":"the user has
//!      not finished authorizing yet"}`。
//!
//! 只认「200 + pending」那一种会让每次轮询都落进 `parse_token_response`，
//! 报出「令牌响应缺少 access_token」—— 用户看到的是一句与授权状态无关的
//! 解析错误，而实际上一切正常、只是在等用户点确认。这个 bug 的隐蔽之处是
//! **它看起来像「登录成功但没返回账号」**：失败在前一步就发生了。
//!
//! 所以下面按 `error` 字段优先判（不看状态码），状态码只用来区分「成功」。
//!
//! ── PKCE 为什么必须真算 ──────────────────────────────────────
//! 上游校验 `code_verifier` 与申请设备码时给的 `code_challenge` 是否匹配
//! （S256）。随便填一个值会在换 token 时被拒，而错误文案只说
//! `invalid_grant` —— 排查方向会被完全带偏。

use base64::Engine;
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::credentials::{self, Credentials};
use super::product;

/// 设备授权的一次会话（登录流程的中间状态）。
pub struct DeviceAuthorization {
    pub device_code: String,
    pub code_verifier: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    pub expires_in_sec: i64,
    pub interval_sec: i64,
}

/// 轮询结果。
pub enum PollOutcome {
    /// 拿到令牌
    Granted(Credentials),
    /// 用户在浏览器里拒绝了
    Denied,
    /// 设备码过期
    Expired,
    Failed(String),
}

/// 生成 PKCE 的 `code_verifier` / `code_challenge`（S256）。
///
/// verifier 用 32 字节随机数 → base64url 无填充（43 字符，符合 RFC 7636 的
/// 43~128 长度要求）；challenge = base64url(sha256(verifier))。
fn create_pkce() -> Result<(String, String), String> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|error| format!("生成 PKCE 随机数失败：{error}"))?;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let verifier = b64.encode(bytes);
    let challenge = b64.encode(Sha256::digest(verifier.as_bytes()));
    Ok((verifier, challenge))
}

fn text_of(body: &Value, key: &str) -> String {
    body.get(key)
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string()
}

/// 申请设备码。
pub async fn start_device(client: &reqwest::Client) -> Result<DeviceAuthorization, String> {
    let (code_verifier, code_challenge) = create_pkce()?;
    let form = [
        ("client_id", product::CLIENT_ID.to_string()),
        ("scope", product::SCOPE.to_string()),
        ("audience", product::AUDIENCE.to_string()),
        ("code_challenge", code_challenge),
        ("code_challenge_method", "S256".to_string()),
    ];
    let response = client
        .post(format!("{}{}", product::ACCOUNT_HOST, product::DEVICE_CODE_PATH))
        .form(&form)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|error| format!("设备码申请失败：{error}"))?;
    let status = response.status().as_u16();
    let body: Value = response.json().await.unwrap_or(Value::Null);
    if !(200..300).contains(&status) {
        return Err(format!("MiniMax 设备码申请失败（HTTP {status}）"));
    }
    let device_code = text_of(&body, "device_code");
    let user_code = text_of(&body, "user_code");
    let verification_uri = {
        let uri = text_of(&body, "verification_uri");
        if uri.is_empty() { text_of(&body, "verification_url") } else { uri }
    };
    let expires_in = body.get("expires_in").and_then(Value::as_i64).unwrap_or(0);
    if device_code.is_empty() || user_code.is_empty() || verification_uri.is_empty() || expires_in <= 0 {
        return Err("MiniMax 设备码响应无法解析".to_string());
    }
    let verification_uri_complete = {
        let complete = text_of(&body, "verification_uri_complete");
        if complete.is_empty() { verification_uri.clone() } else { complete }
    };
    Ok(DeviceAuthorization {
        device_code,
        code_verifier,
        user_code,
        verification_uri,
        verification_uri_complete,
        expires_in_sec: expires_in,
        // 缺省 5 秒（与 asar 默认值一致）
        interval_sec: body
            .get("interval")
            .and_then(Value::as_i64)
            .filter(|value| *value > 0)
            .unwrap_or(5),
    })
}

/// 轮询一次（由调用方按 `interval_sec` 驱动）。
pub async fn poll_once(
    client: &reqwest::Client,
    auth: &DeviceAuthorization,
) -> PollOutcome {
    let form = [
        (
            "grant_type",
            "urn:ietf:params:oauth:grant-type:device_code".to_string(),
        ),
        ("device_code", auth.device_code.clone()),
        ("client_id", product::CLIENT_ID.to_string()),
        ("code_verifier", auth.code_verifier.clone()),
    ];
    let response = match client
        .post(format!("{}{}", product::ACCOUNT_HOST, product::TOKEN_PATH))
        .form(&form)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) => return PollOutcome::Failed(format!("换令牌请求失败：{error}")),
    };
    let status = response.status().as_u16();
    let body: Value = response.json().await.unwrap_or(Value::Null);
    let ok = (200..300).contains(&status);
    let state = text_of(&body, "status");
    let error = text_of(&body, "error");
    // ── 判定顺序：先认 `error` 字段，再看状态码 ────────────────────
    // 上游对「还在等用户授权」回的是 **HTTP 400**，不是 200。把状态码写进
    // 「等」那几支的匹配条件（早先的写法是 `(true, "", "authorization_pending")`）
    // 会让这种情况一路落到 `parse_token_response`，报「缺少 access_token」。
    // 所以除「成功」外一律不看状态码 —— OAuth 的错误语义全在 `error` 里。
    match (ok, state.as_str(), error.as_str()) {
        // 形态一：HTTP 200 + status:"pending"
        (true, "pending", _) | (_, _, "authorization_pending") => {
            PollOutcome::Failed("__pending__".to_string())
        }
        (true, "slow_down", _) | (_, _, "slow_down") => {
            PollOutcome::Failed("__slow_down__".to_string())
        }
        (true, "denied", _) | (true, "access_denied", _) | (_, _, "access_denied") => {
            PollOutcome::Denied
        }
        (true, "expired", _) | (_, _, "expired_token") => PollOutcome::Expired,
        // 只有「HTTP 2xx 且没有 error」才当作拿到了令牌
        (true, "", "") => match credentials::parse_token_response(&body) {
            Ok(credentials) => PollOutcome::Granted(credentials),
            Err(message) => PollOutcome::Failed(message),
        },
        // 其余非 2xx：把上游的 error / error_description 原样带出来，比
        // 「缺少 access_token」有用得多（`invalid_grant` 要用户重新登录，
        // 网络类问题可以重试，处置完全不同）
        (false, _, _) => PollOutcome::Failed(describe_error(&body, status)),
        _ => match credentials::parse_token_response(&body) {
            Ok(credentials) => PollOutcome::Granted(credentials),
            Err(message) => PollOutcome::Failed(message),
        },
    }
}

/// 非 2xx 的错误正文 → 一句能给用户看的话。
///
/// 上游形如 `{"error":"…","error_description":"…"}`，也可能只有 `message`；
/// 三者都取不到时给出状态码，不让调用方看到空字符串。
fn describe_error(body: &Value, status: u16) -> String {
    let code = text_of(body, "error");
    let detail = text_of(body, "error_description");
    if code.is_empty() && detail.is_empty() {
        return format!("换令牌被上游拒绝（HTTP {status}）");
    }
    if detail.is_empty() {
        format!("换令牌被上游拒绝（HTTP {status}）：{code}")
    } else if code.is_empty() {
        format!("换令牌被上游拒绝（HTTP {status}）：{detail}")
    } else {
        format!("换令牌被上游拒绝（HTTP {status}）：{code}（{detail}）")
    }
}

/// 用 refresh_token 续期。
pub async fn refresh(
    client: &reqwest::Client,
    refresh_token: &str,
) -> Result<Credentials, String> {
    if refresh_token.trim().is_empty() {
        return Err("该账号没有 refreshToken，无法续期".to_string());
    }
    let form = [
        ("grant_type", "refresh_token".to_string()),
        ("refresh_token", refresh_token.to_string()),
        ("client_id", product::CLIENT_ID.to_string()),
        ("scope", product::SCOPE.to_string()),
        ("audience", product::AUDIENCE.to_string()),
    ];
    let response = client
        .post(format!("{}{}", product::ACCOUNT_HOST, product::TOKEN_PATH))
        .form(&form)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|error| format!("续期请求失败：{error}"))?;
    let status = response.status().as_u16();
    let body: Value = response.json().await.unwrap_or(Value::Null);
    if !(200..300).contains(&status) {
        let error = text_of(&body, "error");
        return Err(format!(
            "MiniMax 续期被拒（{}）：请重新登录该账号",
            if error.is_empty() { format!("HTTP {status}") } else { error }
        ));
    }
    let mut next = credentials::parse_token_response(&body)?;
    // 上游可能不返回新的 refresh_token：沿用旧的（否则下次续期会没得用）
    if next.refresh_token.trim().is_empty() {
        next.refresh_token = refresh_token.to_string();
    }
    Ok(next)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// 把 `poll_once` 的判定逻辑单独拿出来测：网络不可注入，但「上游回了什么」
    /// 的解读必须能在此离线校验（这是那个「登录成功却不返回账号」bug 的现场）。
    fn classify(status: u16, body: &Value) -> &'static str {
        let ok = (200..300).contains(&status);
        let state = text_of(body, "status");
        let error = text_of(body, "error");
        match (ok, state.as_str(), error.as_str()) {
            (true, "pending", _) | (_, _, "authorization_pending") => "pending",
            (true, "slow_down", _) | (_, _, "slow_down") => "slow_down",
            (true, "denied", _) | (true, "access_denied", _) | (_, _, "access_denied") => "denied",
            (true, "expired", _) | (_, _, "expired_token") => "expired",
            (true, "", "") => "token",
            (false, _, _) => "error",
            _ => "token",
        }
    }

    /// 实测上游形态：**HTTP 400** + authorization_pending。
    /// 早先的匹配要求 `ok == true`，于是这种行落到解析分支报「缺少
    /// access_token」—— 用户看到的是「登录完成但没有账号」。
    #[test]
    fn pending_is_recognized_on_http_400() {
        let body = json!({
            "error": "authorization_pending",
            "error_description": "the user has not finished authorizing yet"
        });
        assert_eq!(classify(400, &body), "pending");
    }

    /// 同一语义的另一种形态（HTTP 200 + status）也要继续认。
    #[test]
    fn pending_is_recognized_on_http_200_shape() {
        assert_eq!(classify(200, &json!({ "status": "pending" })), "pending");
    }

    #[test]
    fn granted_response_is_parsed_as_token() {
        let body = json!({
            "access_token": "mmoat_abc",
            "refresh_token": "mmort_def",
            "expires_in": 3600
        });
        assert_eq!(classify(200, &body), "token");
        let credentials = credentials::parse_token_response(&body).expect("应解析成功");
        assert_eq!(credentials.access_token, "mmoat_abc");
        assert_eq!(credentials.refresh_token, "mmort_def");
        assert!(credentials.expires_at.is_some());
    }

    #[test]
    fn denied_and_expired_keep_their_meaning_on_non_2xx() {
        assert_eq!(classify(400, &json!({ "error": "access_denied" })), "denied");
        assert_eq!(classify(400, &json!({ "error": "expired_token" })), "expired");
    }

    /// 非 2xx 且错误不可识别时，文案要带上游原文而不是空串。
    #[test]
    fn describe_error_carries_upstream_text() {
        let message = describe_error(
            &json!({ "error": "invalid_grant", "error_description": "code verifier mismatch" }),
            400,
        );
        assert!(message.contains("invalid_grant"), "实际: {message}");
        assert!(message.contains("code verifier mismatch"), "实际: {message}");
        assert!(message.contains("400"), "实际: {message}");
    }

    #[test]
    fn describe_error_degrades_to_status_when_body_is_empty() {
        let message = describe_error(&Value::Null, 502);
        assert!(message.contains("502"), "实际: {message}");
    }
}
