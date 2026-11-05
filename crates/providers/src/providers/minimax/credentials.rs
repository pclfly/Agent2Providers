//! MiniMax 凭据：解析、过期判定、令牌响应。
//!
//! ── 为什么不能靠 JWT 解过期 ──────────────────────────────────
//! 上游的访问令牌前缀是 `mmoat_`、刷新令牌 `mmort_`，**都不是 JWT** ——
//! 串里没有 `exp` 可读。过期时刻必须由 `/oauth2/token` 响应里的
//! `expires_in`（秒）自己算出来并写进账号记录。
//!
//! ── expiresAt 的两种形态都要认 ──────────────────────────────
//! 存量账号里既有毫秒时间戳（网关侧写入），也可能有 ISO 串（早期手工导入）。
//! 解析失败按「未知过期」处理（不当作已过期）—— 那只会导致多一次续期尝试，
//! 而不是把可用账号误判成过期。

use serde_json::{json, Value};

use super::product;

/// 解析后的凭据。
pub struct Credentials {
    /// 访问令牌（`mmoat_...`，或 local-runtime 导入的 JWT）
    pub access_token: String,
    /// 刷新令牌（`mmort_...`；可能为空 —— 只导入过访问令牌的账号）
    pub refresh_token: String,
    /// 过期时刻（毫秒 Unix；`None` = 不知道）
    pub expires_at: Option<i64>,
    /// 上游用户 id（`realUserId`）。**矩阵形态必带**：`/minimax-cloud/*`
    /// 对 JWT 要求 `user_id` 查询参数（见 `methods::control_request`）。
    pub real_user_id: String,
}

/// 提前多久开始续期（毫秒）。
///
/// 与网关侧同值：5 分钟。太短会在长连接上撞过期，太长会频繁换令牌
/// （上游对刷新有频次限制）。
const REFRESH_AHEAD_MS: i64 = 5 * 60 * 1000;

/// 从账号记录里取凭据。
///
/// 键名按优先级依次尝试：插件新落的（`accessToken`）与存量导入的
/// （`access_token` / `token`）都要认 —— 存量账号是网关侧写的，键名形态
/// 不完全统一。
pub fn from_record(record: &Value) -> Result<Credentials, String> {
    let access_token = crate::store::pick(record, &["accessToken", "access_token", "token"]);
    if access_token.trim().is_empty() {
        return Err("账号缺少访问令牌（MiniMax 需要 mmoat_ 开头的令牌）".to_string());
    }
    let refresh_token = crate::store::pick(record, &["refreshToken", "refresh_token"]);
    let expires_at = record
        .get("expiresAt")
        .or_else(|| record.get("expires_at"))
        .and_then(parse_time);
    // `realUserId` 是上游给的稳定用户 id（导入时写在记录里）。矩阵形态的
    // `user_id` 查询参数要它；缺失时留空 —— 上游会按 token 自行归属，而带一个
    // 错的 id 反而可能被拒。
    let real_user_id = crate::store::pick(
        record,
        &["realUserId", "real_user_id", "realUserID", "userId"],
    );
    Ok(Credentials {
        access_token,
        refresh_token,
        expires_at,
        real_user_id,
    })
}

/// 把 `expiresAt` 的两种形态（毫秒数 / ISO 串）归一成毫秒时间戳。
fn parse_time(value: &Value) -> Option<i64> {
    if let Some(number) = value.as_i64() {
        // 十位数是秒级，十三位是毫秒 —— 存量里两种都出现过
        return Some(if number < 10_000_000_000 {
            number.saturating_mul(1000)
        } else {
            number
        });
    }
    let text = value.as_str()?.trim();
    // ISO 8601（带或不带毫秒 / 时区）→ 毫秒。用 chrono 解析而不是手写，
    // 免得多一种格式就多一处特判。
    chrono::DateTime::parse_from_rfc3339(text)
        .ok()
        .map(|at| at.timestamp_millis())
}

impl Credentials {
    /// 是否临期（或已过期）。`None` 过期时刻按「不临期」处理。
    pub fn expiring(&self) -> bool {
        let Some(at) = self.expires_at else {
            return false;
        };
        let now = chrono::Utc::now().timestamp_millis();
        now + REFRESH_AHEAD_MS >= at
    }

    /// 能否续期（没有刷新令牌就只能重新登录）。
    pub fn can_refresh(&self) -> bool {
        !self.refresh_token.trim().is_empty()
    }

    /// 写回账号记录时用的字段（只含本家认识的键）。
    pub fn to_record(&self, expires_at: Option<i64>) -> Value {
        json!({
            "accessToken": self.access_token,
            "refreshToken": self.refresh_token,
            "expiresAt": expires_at,
        })
    }
}

/// 解析 `/oauth2/token` 的响应。
///
/// 上游成功与刷新共用同一形状：`{access_token, refresh_token, expires_in, ...}`。
/// `expires_in` 是**秒**，这里立刻换算成绝对时刻 —— 相对值落盘等于每次重启
/// 都从「刚获得」重新计时，令牌会永不过期地用到上游拒绝为止。
pub fn parse_token_response(payload: &Value) -> Result<Credentials, String> {
    let access = payload
        .get("access_token")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .ok_or_else(|| "令牌响应缺少 access_token".to_string())?;
    let refresh = payload
        .get("refresh_token")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let expires_at = payload
        .get("expires_in")
        .and_then(Value::as_i64)
        .map(|seconds| chrono::Utc::now().timestamp_millis() + seconds.saturating_mul(1000));
    Ok(Credentials {
        access_token: access.to_string(),
        refresh_token: refresh,
        expires_at,
        // 设备码换来的令牌没有 `realUserId` 可读（令牌不是 JWT）；Bearer
        // 形态也不需要它
        real_user_id: String::new(),
    })
}

/// 令牌前缀是否像本家的（用来在导入时给出可操作的提示）。
pub fn looks_like_access_token(token: &str) -> bool {
    token.trim().starts_with(product::ACCESS_PREFIX)
}
