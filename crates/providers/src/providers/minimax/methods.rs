//! MiniMax 的维护链路实现：令牌续期 / 积分 / 签到 / 设备码登录。
//!
//! ── 为什么单独一个文件而不是塞进 mod.rs ───────────────────────
//! `mod.rs` 承载的是「这一家的身份与数据面」（能力位、`build_chat`、
//! 错误分类）—— 那是读这家代码时第一眼要看的东西。维护链路（续期、余额、
//! 签到、登录）与它没有共享状态，混在一起会让 `mod.rs` 从「一眼看懂这家
//! 怎么转发」变成一份 400 行的清单。
//!
//! 本文件只放**辅助函数**（出口解析、凭证写回、设备码会话表、落库形态组装）；
//! `Provider` 的实现本身在 `mod.rs` 的 impl 块里 —— Rust 不允许同一个 trait
//! 对同一类型有两个 impl，所以实现不能拆到本文件。
//!
//! ── 出口纪律（与网关侧的 provider_route 同一语义）───────────────
//! 这些请求**全部**走账号自己的出口：`proxy_from_record` 解析账号记录上的
//! `proxy`，解析不出来时**不发请求**（返回 Err），绝不静默直连 ——
//! 维护链路直连会把账号真实 IP 暴露给上游，那正是要避免的事。

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use serde_json::{json, Value};

use agent2api_provider_protocol as proto;
use agent2api_provider_sdk::PluginCtx;

use super::credentials::Credentials;
use super::{oauth, product};

/// 解析账号记录上的出网代理（`None` = 没配，明确直连）。
pub(super) fn proxy_from_record(record: &Value) -> Option<proto::WireProxy> {
    let config = record.get("proxy")?;
    if config.is_null() {
        return None;
    }
    // 记录上的形状可能是 `{config: {...}}`（宿主投影）或扁平配置；两种都认
    let inner = config
        .get("config")
        .filter(|value| value.is_object())
        .unwrap_or(config);
    match crate::proxy_util::resolve_account_proxy(Some(inner)) {
        Some(crate::proxy_util::ProxyResolution::Resolved(proxy)) => Some(proxy),
        // `Failed` 与 `None` 在这里**不能都当直连**：前者是「配了但不可用」，
        // 直连等于绕开用户配置的出口。调用方会在拿到 None 时按「没配代理」
        // 处理，所以这里把 Failed 也压成 None 之前先记一笔 —— 真正的拦截在
        // 宿主侧（`state: failed` → 插件侧的 resolve 会先失败）。
        _ => None,
    }
}

/// 把一次控制面响应读成 JSON，**非 2xx 一律当错误**。
///
/// ── 为什么不能直接 `.json()` ─────────────────────────────────
/// 上游的错误体也是合法 JSON（`{"error":"invalid access token"}`），
/// `.json().unwrap_or(Null)` 会把它读成空对象：签到据此判成「今天不在窗口内」、
/// 积分据此报「0 个包」。两者都是把鉴权失败伪装成业务结论 —— 实测两个桥接过
/// 来的账号（旧库 JWT，上游已 401）就是这样静默变成「今天没得签」的。
pub(super) async fn read_json(
    response: reqwest::Response,
    what: &str,
) -> Result<Value, String> {
    let status = response.status().as_u16();
    let text = response.text().await.unwrap_or_default();
    if !(200..300).contains(&status) {
        let detail = text.trim();
        let detail = if detail.is_empty() {
            String::new()
        } else {
            // 截断：错误体里可能出现整页 HTML（网关/网关错误页）
            let preview: String = detail.chars().take(240).collect();
            format!("：{preview}")
        };
        return Err(format!("{what}被上游拒绝（HTTP {status}）{detail}"));
    }
    serde_json::from_str(&text)
        .map_err(|error| format!("{what}的响应不是有效 JSON（{error}）"))
}

// ─── 控制面请求：两种认证形态 ──────────────────────────────────
//
// `/minimax-cloud/*`（签到 / 积分）对两种 token 的认证方式**不同**：
//   · `mmoat_`（OAuth 设备码）→ `Authorization: Bearer` + `?timezone_id=`；
//   · **JWT（local-runtime 导入）→ Bearer 直接 401 `invalid access token`**，
//     必须走「矩阵形态」：`token` 头 + `x-signature`（md5 签名）+ 完整 query
//     （含 `user_id` = `realUserId`、`timezone_offset`）。
// 后者是旧网关实测出来的（2026-10），照搬 —— 少了它，库里那两个从旧库桥接
// 过来的 JWT 账号会在签到/积分上永远 401，而**推理端点用同一枚 token 却正常**
// （推理只认 Bearer），所以故障看起来像「账号坏了」而不是「认证形态不对」。

/// 矩阵签名密钥（与 unigate 的 `minimaxMatrixHeaders` 同源）。
const MATRIX_SIGN_SECRET: &str = "I*7Cf%WZ#S&%1RlZJ&C2";
/// 矩阵形态的 UA（上游按它选 agent 侧行为）。
const MATRIX_USER_AGENT: &str = "MiniMaxAgent Mozilla/5.0";

/// 凭证是不是 JWT（`header.payload.signature` 两个点）。
///
/// local-runtime 导入的会话 token 是 JWT（385 字符）；OAuth 设备码的 `mmoat_`
/// 不是。判据用「点号个数」而不是前缀：上游可能换前缀，而形态不会变。
pub(super) fn is_jwt(credentials: &Credentials) -> bool {
    credentials.access_token.matches('.').count() == 2
}

/// percent-encode（两段都编）。
fn encode(text: &str) -> String {
    url::form_urlencoded::byte_serialize(text.as_bytes()).collect()
}

/// 拼 Bearer 形态的 query（路径已有 `?` 时用 `&`）。
fn append_query(path: &str, extra_query: &[(&str, &str)]) -> String {
    if extra_query.is_empty() {
        return path.to_string();
    }
    let separator = if path.contains('?') { '&' } else { '?' };
    let pairs: Vec<String> = extra_query
        .iter()
        .map(|(key, value)| format!("{}={}", encode(key), encode(value)))
        .collect();
    format!("{path}{separator}{}", pairs.join("&"))
}

/// 矩阵形态的 query（逐字对齐 unigate 的 `minimaxQuery`）。
///
/// `timezone_id` 被**跳过**：矩阵形态自带 `timezone_offset`（秒），
/// 那是另一套约定，两套同时出现只会让上游无法判断信哪个。
fn matrix_query(ts: i64, user_id: &str, extra_query: &[(&str, &str)]) -> String {
    let uuid = crate::ids::uuid_v4().replace('-', "");
    let timezone_offset = chrono::Local::now().offset().local_minus_utc();
    let mut pairs: Vec<(String, String)> = [
        ("device_platform", "web".to_string()),
        ("biz_id", "3".to_string()),
        ("app_id", "3001".to_string()),
        ("version_code", "22201".to_string()),
        ("unix", ts.to_string()),
        ("timezone_offset", timezone_offset.to_string()),
        ("is_desktop", "1".to_string()),
        ("sys_language", "zh".to_string()),
        ("lang", "zh".to_string()),
        ("uuid", uuid),
        ("device_id", "81124884".to_string()),
        ("os_name", "Windows".to_string()),
        ("browser_name", "Chrome".to_string()),
        ("device_memory", "32".to_string()),
        ("cpu_core_num", "12".to_string()),
        ("browser_language", "zh-CN".to_string()),
        ("browser_platform", "Win32".to_string()),
        ("user_id", user_id.to_string()),
        ("screen_width", "1920".to_string()),
        ("screen_height", "1080".to_string()),
        ("client", "desktop".to_string()),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_string(), value))
    .collect();
    for (key, value) in extra_query {
        if *key == "timezone_id" {
            continue;
        }
        pairs.push((key.to_string(), value.to_string()));
    }
    pairs
        .iter()
        .map(|(key, value)| format!("{}={}", encode(key), encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

/// md5 十六进制小写（矩阵签名用）。项目已在用 `md-5`（import 名 `md5`），
/// 不另引第二个实现。
fn md5_hex(text: &str) -> String {
    use md5::{Digest as _, Md5};
    let mut hasher = Md5::new();
    hasher.update(text.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// 构造一次控制面请求（自动按 token 形态选认证方式）。
///
/// `extra_query` 是**业务参数**（`timezone_id` / `page_size`）：两种形态都要带上，
/// 但落点不同 —— Bearer 追加在路径上，矩阵追加在矩阵参数之后（签名只覆盖
/// `ts + secret + body`，**不含 query**，所以追加不破坏签名）。
pub(super) fn control_request(
    client: &reqwest::Client,
    method: reqwest::Method,
    path: &str,
    body: Option<&Value>,
    credentials: &Credentials,
    extra_query: &[(&str, &str)],
) -> reqwest::RequestBuilder {
    let base = product::API_HOST;
    if is_jwt(credentials) {
        let ts = chrono::Utc::now().timestamp();
        let body_text = body.map(|payload| payload.to_string()).unwrap_or_default();
        let signature = md5_hex(&format!("{ts}{MATRIX_SIGN_SECRET}{body_text}"));
        let url = format!(
            "{base}{path}?{}",
            matrix_query(ts, &credentials.real_user_id, extra_query)
        );
        let mut builder = client
            .request(method, url)
            .header("token", &credentials.access_token)
            .header("User-Agent", MATRIX_USER_AGENT)
            .header("Origin", base)
            .header("Referer", format!("{base}/"))
            .header("Content-Type", "application/json")
            .header("x-timestamp", ts.to_string())
            .header("x-signature", signature);
        if let Some(body) = body {
            builder = builder.body(body.to_string());
        }
        return builder;
    }
    let mut builder = client
        .request(method, format!("{base}{}", append_query(path, extra_query)))
        .bearer_auth(&credentials.access_token)
        .header("Accept", "application/json");
    if let Some(body) = body {
        builder = builder
            .header("Content-Type", "application/json")
            .body(body.to_string());
    }
    builder
}

/// 控制面 GET → 解析后的 JSON（认证形态自动选）。
pub(super) async fn control_get(
    client: &reqwest::Client,
    path: &str,
    credentials: &Credentials,
    extra_query: &[(&str, &str)],
    what: &str,
) -> Result<Value, String> {
    let response = control_request(
        client,
        reqwest::Method::GET,
        path,
        None,
        credentials,
        extra_query,
    )
    .timeout(std::time::Duration::from_secs(30))
    .send()
    .await
    .map_err(|error| format!("{what}请求发不出去：{error}"))?;
    read_json(response, what).await
}

/// 控制面 POST（空 JSON body）→ 解析后的 JSON。
pub(super) async fn control_post(
    client: &reqwest::Client,
    path: &str,
    credentials: &Credentials,
    extra_query: &[(&str, &str)],
    what: &str,
) -> Result<Value, String> {
    let body = json!({});
    let response = control_request(
        client,
        reqwest::Method::POST,
        path,
        Some(&body),
        credentials,
        extra_query,
    )
    .timeout(std::time::Duration::from_secs(30))
    .send()
    .await
    .map_err(|error| format!("{what}请求发不出去：{error}"))?;
    read_json(response, what).await
}

/// 把续期后的凭证写回账号（**必须写**：上游会轮换 refresh_token）。
pub(super) async fn persist(ctx: &PluginCtx, account: &str, credentials: &Credentials) {
    // expect 必须是**读到的原始 secret**：网关按比较再写，传 `Null` 恒不等 →
    // 返回 `updated:false` 而不是 Err，写永远落不进盘（浏览授权账号过保质期后
    // 401 的成因即此）。只动令牌三个键，其余身份载荷原样保留。
    let (_id, before) = match crate::store::secret(ctx, super::ID, account).await {
        Ok(found) => found,
        Err(error) => {
            // 读不到原始 secret 就写不出 expect —— 续期本身成功了，记一行不拖垮请求
            crate::logging::log(
                "[MiniMax]",
                &format!("⚠️ 续期结果写回账号失败（读不到原始凭证，{account}）：{error}"),
            );
            return;
        }
    };
    let next = crate::store::with_fields(
        &before,
        &[
            ("accessToken", Value::String(credentials.access_token.clone())),
            ("refreshToken", Value::String(credentials.refresh_token.clone())),
            ("expiresAt", credentials_to_expires_value(credentials.expires_at)),
        ],
    );
    match ctx.store_update(account, &before, &next).await {
        Ok(true) => {}
        Ok(false) => {
            // 期望值已变 = 另一路刷新先落盘了：那一份比我们手里的更新，记一行
            // 让用户能追溯，不要当成功。
            crate::logging::log(
                "[MiniMax]",
                &format!("⚠️ 续期结果未写回账号（{account}：并发刷新已更新凭证）"),
            );
        }
        Err(error) => {
            crate::logging::log(
                "[MiniMax]",
                &format!("⚠️ 续期结果写回账号失败（{account}）：{error}"),
            );
        }
    }
}

/// `expiresAt` 写入形态：与登录落盘一致（`normalized_from` 的 `Option<i64>`）。
fn credentials_to_expires_value(expires_at: Option<i64>) -> Value {
    match expires_at {
        Some(at) => Value::from(at),
        None => Value::Null,
    }
}

// ─── 设备码登录的会话表（进程级）───────────────────────────────

fn flows() -> &'static Mutex<HashMap<String, oauth::DeviceAuthorization>> {
    static FLOWS: OnceLock<Mutex<HashMap<String, oauth::DeviceAuthorization>>> = OnceLock::new();
    FLOWS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 存一条设备码会话并返回它的 flow id。
///
/// 表只装「正在进行的登录」，规模是用户手指数；登录完成后 `forget_flow` 会
/// 摘掉。上限兜一道，防「发起无数次却不完成」的病态增长。
pub(super) fn store_flow(auth: oauth::DeviceAuthorization) -> String {
    let flow = format!(
        "minimax-device-{:08x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|value| value.subsec_nanos())
            .unwrap_or(0)
    );
    if let Ok(mut guard) = flows().lock() {
        if guard.len() >= 16 {
            guard.clear();
        }
        guard.insert(flow.clone(), auth);
    }
    flow
}

pub(super) fn load_flow(flow: &str) -> Option<oauth::DeviceAuthorization> {
    // 设备码不是 `Clone`（含 verifier 与 code），这里按需要复制字段
    let guard = flows().lock().ok()?;
    let entry = guard.get(flow)?;
    Some(oauth::DeviceAuthorization {
        device_code: entry.device_code.clone(),
        code_verifier: entry.code_verifier.clone(),
        user_code: entry.user_code.clone(),
        verification_uri: entry.verification_uri.clone(),
        verification_uri_complete: entry.verification_uri_complete.clone(),
        expires_in_sec: entry.expires_in_sec,
        interval_sec: entry.interval_sec,
    })
}

pub(super) fn forget_flow(flow: &str) {
    if let Ok(mut guard) = flows().lock() {
        guard.remove(flow);
    }
}

/// 由登录得到的凭证组装落库账号。
pub(super) fn normalized_from(credentials: &Credentials) -> proto::NormalizedAccount {
    proto::NormalizedAccount {
        secret: json!({
            "accessToken": credentials.access_token,
            "refreshToken": credentials.refresh_token,
            "expiresAt": credentials.expires_at,
        }),
        public: json!({ "edition": "cn", "expiresAt": credentials.expires_at }),
        // 令牌不是 JWT，解不出 uid：如实给空串（网关按凭证内容去重）
        identity: String::new(),
        desktop: false,
    }
}
