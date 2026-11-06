//! MiniMax Code（中国版）提供商。
//!
//! ── 上游长什么样（移植自网关侧实现，来源为参考实现 `src/minimax*.ts`）──
//!   - 推理：`POST {API_HOST}/mavis/api/v1/llm/v1/messages`，**Anthropic
//!     Messages 协议**（`system` 顶层字段、`tool_use` / `tool_result` 块、
//!     图片 `source.type=base64` 裸 base64）。
//!   - 登录：OAuth 设备码 + PKCE S256（`account.minimax.cn`），与 Qoder /
//!     Cline 的设备授权同形。
//!   - 凭据：token 前缀 `mmoat_` / `mmort_`，**不是 JWT** —— `expires_at`
//!     必须由 `expires_in` 自算写入（见 `credentials.rs`）。
//!
//! ── 为什么走无状态路径 ──────────────────────────────────────
//! 上游是「一问一答 + SSE」，没有会话建连 / 工具循环那套状态机。所以
//! `capabilities.stateful = false`，走 `build_chat`：插件只负责把 chat 体
//! 翻成 Anthropic 体并声明 `upstream: Anthropic`，流翻译、usage、错误分类
//! 都由网关的共享层负责。
//!
//! ── 本版范围 ──────────────────────────────────────────────
//! 已实现：无状态转发、模型目录（远程 + 兜底）、账号规范化（粘贴令牌）、
//! OAuth 设备码登录（`oauth.rs`）、令牌自动续期（`refresh` / `refresh_token`
//! 两个能力位均为 true）、积分查询（`usage.rs`）、每日签到（`checkin.rs`）。
//!
//! ── 为什么没有申报领取类（`claims`）────────────────────────
//! 上游只有「签到」与「积分明细」两个入口，没有新手礼 / 每日任务 / 限时套餐
//! 那一类可领取的活动 —— `product.rs` 里除登录、目录、推理之外的端点只有
//! `SIGNIN_STATUS_PATH` / `SIGNIN_CLAIM_PATH` / `CREDIT_DETAILS_PATH` 三个。
//! 所以 `claims` 申报 false。这不是「还没做」（口径见网关 README 的支持矩阵：
//! ✗ 必须能说清是怎么排除的，不是尚未实现）。
//!
//! ── panic=abort ────────────────────────────────────────────
//! 本目录零 unwrap/expect/panic，不持任何锁跨 await。

mod chat;
mod checkin;
mod methods;
mod credentials;
mod oauth;
mod product;
mod usage;

use std::sync::{Mutex, OnceLock};

use serde_json::{json, Value};

use agent2api_provider_protocol as proto;
use agent2api_provider_sdk::{ChatPlan, PluginCtx, Provider, ProviderMeta, SendFuture};

use crate::errors::GatewayError;

/// provider id（`pack.json` 里必须写同一个值）。
pub const ID: &str = "minimax";

pub struct MiniMaxProvider;

impl Provider for MiniMaxProvider {
    fn meta(&self) -> ProviderMeta {
        ProviderMeta::new(ID, "MiniMax")
            .with_capabilities(proto::Capabilities {
                chat: true,
                // 上游没有会话建连 / 工具循环的状态机
                stateful: false,
                // 支持 refresh_token 续期（见 oauth.rs）
                refresh: true,
                model_refresh: true,
                usage: true,
                checkin: true,
                claims: false,
                // 设备码授权：登录时拉起浏览器
                web_login: true,
                // 上游回的模型名是「官方名」（MiniMax-M3），客户端可能请求小写
                sse_model_rewrite: true,
                sse_strip_newline_chunks: false,
                anonymous_default_session: false,
                system_proxy_when_unset: false,
                refresh_uses_account: true,
                supports_default_model: false,
                env_credentials: false,
            })
            .with_login(vec![
                proto::LoginMethod::Token {
                    label: "访问令牌".into(),
                    placeholder: "粘贴 mmoat_ 开头的令牌".into(),
                    extra_fields: vec![],
                },
                proto::LoginMethod::Browser {
                    button: "用 MiniMax 账号登录".into(),
                    hint: Some("会打开官方授权页；在页面上确认后本机自动完成登录".into()),
                },
            ])
            .with_models(
                product::DEFAULT_MODELS
                    .iter()
                    .map(|(id, name)| json!({ "id": id, "name": name }))
                    .collect(),
            )
            .with_account_features(proto::AccountFeatures {
                usage: true,
                credit_detail: true,
                credit_expiry: false,
                usage_detail: false,
                edition: true,
                identifier: vec!["userId".to_string()],
                expiry: vec!["expiresAt".to_string()],
                long_lived: false,
                claim: false,
                plan_channel: false,
                email_as_name: false,
                concurrency_default: None,
                default_limiters: None,
            })
    }

    /// 无状态转发：构造 Anthropic Messages 请求。
    fn build_chat<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        req: proto::ChatRequest,
    ) -> SendFuture<'a, ChatPlan> {
        Box::pin(async move {
            let record = crate::store::record(ctx, ID, &req.account).await?;
            let credentials = credentials::from_record(&record)
                .map_err(|message| GatewayError::with_status(401, message))?;
            if credentials.expiring() {
                crate::logging::verbose(
                    "[MiniMax]",
                    "访问令牌已临期或过期；本版不支持自动续期，请在账号页重新粘贴令牌",
                );
            }
            let body = chat::build_messages_body(&req.body, &req.wire_model, &req.reasoning)
                .map_err(|message| GatewayError::with_status(400, message))?;
            Ok(ChatPlan {
                url: format!("{}{}", product::API_HOST, product::INFER_PATH),
                headers: vec![
                    (
                        "Authorization".to_string(),
                        format!("Bearer {}", credentials.access_token),
                    ),
                    (
                        "anthropic-version".to_string(),
                        product::ANTHROPIC_VERSION.to_string(),
                    ),
                    ("Content-Type".to_string(), "application/json".to_string()),
                ],
                body,
                // 上游说 Anthropic Messages —— 网关据此选翻译机
                upstream: proto::UpstreamKind::Anthropic,
            })
        })
    }

    /// 动态登录方式（网关「添加账号」弹窗按它渲染表单）。
    ///
    /// ── 为什么必须实现（2026-11 修）─────────────────────────────
    /// 网关优先问 `auth.methods`；不实现时**整块降级成「手动凭证 JSON」**，
    /// 用户看不到「用 MiniMax 账号登录」这个入口 —— 而 `login_start` /
    /// `login_poll` / `login_cancel` 三条（设备码 + PKCE）本来就是通的，
    /// 只差把方式清单报出去。症状是「有实现但没有按钮」。
    ///
    /// `methodIndex` 只用于界面区分；真正发起登录时网关固定传
    /// `method: "browser"`，具体走哪条由 `login_start` 内部的 method 判断
    /// 决定（见那里的说明）。
    fn admin_action<'a>(
        &'a self,
        _ctx: &'a PluginCtx,
        _account: &'a str,
        action: &'a str,
        _payload: &'a Value,
    ) -> SendFuture<'a, Value> {
        Box::pin(async move {
            match action {
                "auth.methods" => Ok(login_methods()),
                other => Err(agent2api_provider_sdk::unsupported(format!(
                    "MiniMax 不支持管理动作「{other}」"
                ))),
            }
        })
    }

    /// 上游 401/403 一律按「令牌失效」处置（引导用户重新粘贴）。
    fn classify(&self, status: u16, body: &Value) -> proto::ErrorClass {
        // 上游的错误体常带 `base_resp.status_msg`，把它带给用户比「HTTP 401」有用
        let message = body
            .pointer("/base_resp/status_msg")
            .or_else(|| body.get("message"))
            .or_else(|| body.get("error"))
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| format!("MiniMax 上游返回 HTTP {status}"));
        let upstream_code = body
            .pointer("/base_resp/status_code")
            .and_then(Value::as_i64);
        match status {
            401 | 403 => proto::ErrorClass::TokenExpired {
                message: format!("MiniMax 凭证失效，请重新粘贴令牌：{message}"),
            },
            429 => proto::ErrorClass::QuotaLimited {
                reset_at: None,
                message,
                upstream_code,
                status,
            },
            _ => proto::ErrorClass::Fatal {
                status,
                message,
                upstream_code,
            },
        }
    }

    /// 模型目录：远程清单 + 兜底表。
    ///
    /// 上游是 `{providers:[{config:{models:{<id>:{name,reasoning,...}}}}]}` 形态
    /// （**不是** OpenAI 的 `{data:[{id}]}`，也不是数组），所以逐项映射而不是
    /// 直接透传 —— `id` 取自 map 的键，能力位取自各自字段。
    ///
    /// ── 为什么读缓存而不是每次现拉 ──────────────────────────────
    /// 宿主在「刷新模型清单」里会先发 `models.refresh` 再发 `models.list`；
    /// 若 `models` 自己也出网，一次刷新就是两次上游往返（且第二次失败还会把
    /// 「刚刷新成功」的结论翻掉）。这里读进程内快照，`refresh_models` 负责
    /// 真正拉取。没刷过时回落内置表并如实标 `remote=false`。
    fn models<'a>(
        &'a self,
        _ctx: &'a PluginCtx,
        _account: &'a str,
    ) -> SendFuture<'a, proto::ModelList> {
        Box::pin(async move { Ok(cached_catalog().unwrap_or_else(builtin_catalog)) })
    }

    /// 真正拉一次远程目录并写进进程内快照。
    ///
    /// ── 目录端点本身是公开的 ────────────────────────────────────
    /// 不带凭证也回 200。但仍然用**账号自己的出口**（记录上的 `proxy`）：
    /// 出口一致性优先于「少一次鉴权」—— 目录请求同样会暴露本机 IP。
    /// 账号记录取不到时明确直连（`proxy_from_record` 对缺失返回 `None`）。
    fn refresh_models<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        account: &'a str,
        _force: bool,
    ) -> SendFuture<'a, proto::RefreshOutcome> {
        Box::pin(async move {
            let record = match crate::store::record(ctx, ID, account).await {
                Ok(record) => record,
                // 没账号 →「没刷」而不是「失败」：用户点刷新不该看到红字
                Err(error) => {
                    crate::logging::verbose(
                        "[MiniMax]",
                        &format!("模型目录刷新跳过：{error}"),
                    );
                    return Ok(proto::RefreshOutcome::unchanged());
                }
            };
            let proxy = methods::proxy_from_record(&record);
            let client = crate::http::control_client(proxy.as_ref(), &ctx.env.proxy);
            match fetch_catalog(&client).await {
                Ok(models) if !models.is_empty() => {
                    let count = models.len();
                    store_catalog(models);
                    Ok(proto::RefreshOutcome::refreshed(count))
                }
                // 200 但认不出形状：如实报「没刷」，别把空目录当成刷新成功
                Ok(_) => Ok(proto::RefreshOutcome::failed(
                    "模型目录响应无法解析（未找到 providers[].config.models）",
                )),
                Err(error) => Ok(proto::RefreshOutcome::failed(error)),
            }
        })
    }

    /// 账号规范化：把用户粘贴的令牌归一成插件认识的字段形态。
    fn normalize_account<'a>(
        &'a self,
        _ctx: &'a PluginCtx,
        input: proto::NormalizeInput,
    ) -> SendFuture<'a, proto::NormalizedAccount> {
        Box::pin(async move {
            // 文本来源两种：手填表单（`payload` 里的字段）与文件全文。
            // 手填的键名按前端表单约定取 `accessToken` / `token`。
            let text = match &input.source {
                proto::NormalizeSource::Manual { payload } => crate::store::pick(
                    payload,
                    &["accessToken", "access_token", "token", "apiKey"],
                ),
                proto::NormalizeSource::FileText { content, .. } => content.clone(),
                _ => String::new(),
            };
            let text = text.trim().to_string();
            if text.is_empty() {
                return Err("请粘贴 MiniMax 访问令牌（mmoat_ 开头）".to_string());
            }
            // 也接受整份 auth.json（用户直接从客户端目录拷过来的情况）
            if text.starts_with('{') {
                if let Ok(parsed) = serde_json::from_str::<Value>(&text) {
                    let token = crate::store::pick(
                        &parsed,
                        &["accessToken", "access_token", "token"],
                    );
                    if !token.trim().is_empty() {
                        return Ok(normalized(token, ""));
                    }
                }
                return Err("这段 JSON 里没有 accessToken 字段".to_string());
            }
            // ── 贴错东西的两种常见形态，各给一句能照着做的提示 ──────────
            // 刷新令牌（`mmort_`）：它换不出「直接可用的访问令牌」，贴进来只会
            // 在第一次转发时 401。
            if text.starts_with(product::REFRESH_PREFIX) {
                return Err(
                    "这是刷新令牌（mmort_ 开头），不能直接用于请求；请填访问令牌（mmoat_ 开头）"
                        .to_string(),
                );
            }
            // 既不是 `mmoat_`、也不是 JWT（local-runtime 导入的会话 token 是
            // 三段式的 JWT）：多半是把 API Key 或别的什么东西贴上来了。
            // 判据只看形态，不阻断 —— 上游换前缀时不至于连账号都存不进去。
            if !credentials::looks_like_access_token(&text)
                && text.matches('.').count() != 2
            {
                crate::logging::warn(
                    "[MiniMax]",
                    "令牌不像 mmoat_ 前缀也不是 JWT，仍按访问令牌保存（上游换形态时不至于存不进去）",
                );
            }
            Ok(normalized(text, ""))
        })
    }


    /// 取一个现在能用的令牌（临期则先续期）。
    ///
    /// ── 续期结果必须落库 ────────────────────────────────────────
    /// 上游换令牌时会**轮换** refresh_token：只更新内存而不写回账号，下次重启
    /// 就只能用已作废的旧 refresh_token，表现为「昨天还好好的，今天怎么都登不上」。
    fn ensure_token<'a>(&'a self, ctx: &'a PluginCtx, account: &'a str) -> SendFuture<'a, String> {
        Box::pin(async move {
            let record = crate::store::record(ctx, ID, account).await?;
            let credentials = credentials::from_record(&record)
                .map_err(|message| GatewayError::with_status(401, message))?;
            if !credentials.expiring() {
                return Ok(credentials.access_token);
            }
            if !credentials.can_refresh() {
                crate::logging::verbose(
                    "[MiniMax]",
                    "访问令牌已临期且没有 refreshToken：请在账号页重新登录",
                );
                return Ok(credentials.access_token);
            }
            let proxy = methods::proxy_from_record(&record);
            let client = crate::http::control_client(proxy.as_ref(), &ctx.env.proxy);
            let refreshed = oauth::refresh(&client, &credentials.refresh_token)
                .await
                .map_err(|message| GatewayError::with_status(401, message))?;
            methods::persist(ctx, account, &refreshed).await;
            crate::logging::log("[MiniMax]", "访问令牌已续期");
            Ok(refreshed.access_token)
        })
    }

    /// 401 之后的无条件续期。
    fn refresh_token<'a>(&'a self, ctx: &'a PluginCtx, account: &'a str) -> SendFuture<'a, String> {
        Box::pin(async move {
            let record = crate::store::record(ctx, ID, account).await?;
            let credentials = credentials::from_record(&record)
                .map_err(|message| GatewayError::with_status(401, message))?;
            if !credentials.can_refresh() {
                return Err("该账号没有 refreshToken，无法续期：请在账号页重新登录".to_string());
            }
            let proxy = methods::proxy_from_record(&record);
            let client = crate::http::control_client(proxy.as_ref(), &ctx.env.proxy);
            let refreshed = oauth::refresh(&client, &credentials.refresh_token).await?;
            methods::persist(ctx, account, &refreshed).await;
            Ok(refreshed.access_token)
        })
    }

    /// 凭证是否临期（网关据此提前触发续期）。
    fn token_expiring<'a>(&'a self, ctx: &'a PluginCtx, account: &'a str) -> SendFuture<'a, bool> {
        Box::pin(async move {
            let record = crate::store::record(ctx, ID, account).await?;
            Ok(credentials::from_record(&record)
                .map(|credentials| credentials.expiring())
                .unwrap_or(false))
        })
    }

    /// 积分明细：逐包求和（`page_size=100`，理由见 `usage.rs` 的模块头）。
    fn usage<'a>(&'a self, ctx: &'a PluginCtx, account: &'a str) -> SendFuture<'a, Value> {
        Box::pin(async move {
            let record = crate::store::record(ctx, ID, account).await?;
            let credentials = credentials::from_record(&record)
                .map_err(|message| GatewayError::with_status(401, message))?;
            let proxy = methods::proxy_from_record(&record);
            let client = crate::http::control_client(proxy.as_ref(), &ctx.env.proxy);
            // `page_size` 必须显式带（不带时上游只回 20 条，余额会少算，见
            // `usage.rs` 模块头）；`PAGE_MAX` 是唯一事实来源，不另写一个字面量
            let page_size = usage::PAGE_MAX.to_string();
            let body = methods::control_get(
                &client,
                product::CREDIT_DETAILS_PATH,
                &credentials,
                &[("page_size", page_size.as_str())],
                "积分查询",
            )
            .await?;
            let summary = usage::parse_credit_details(&body)?;
            Ok(usage::report_json(&summary))
        })
    }

    /// 每日签到：先查状态，没签才领。
    ///
    /// ── 为什么先查再领 ──────────────────────────────────────────
    /// 上游对「今天已领过」的二次领取回 `claim_result=2`（HTTP 200）；而对
    /// **不能领**的账号直接领会走到「缺少有效 claim_result」那条错误上，文案
    /// 比状态查询给出的原因难懂得多。
    fn checkin<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        account: &'a str,
    ) -> SendFuture<'a, proto::CheckinReport> {
        Box::pin(async move {
            let record = crate::store::record(ctx, ID, account).await?;
            let credentials = credentials::from_record(&record)
                .map_err(|message| GatewayError::with_status(401, message))?;
            let proxy = methods::proxy_from_record(&record);
            let client = crate::http::control_client(proxy.as_ref(), &ctx.env.proxy);
            // 签到两个端点都必须带 `timezone_id`（IANA 名）：按客户端上报的
            // 时区结算，漏了会被判成「今天还没到」。JWT 走矩阵形态时这个参数
            // 由 `timezone_offset` 取代（见 `methods::control_request`）。
            let timezone = checkin::timezone_id();
            let query = [("timezone_id", timezone.as_str())];

            let status_body = methods::control_get(
                &client,
                product::SIGNIN_STATUS_PATH,
                &credentials,
                &query,
                "签到状态查询",
            )
            .await?;
            let status = checkin::parse_status(&status_body)?;
            crate::logging::verbose(
                "[MiniMax]",
                &format!("签到状态 {}", checkin::status_summary(&status)),
            );
            if status.claimed_today {
                return Ok(proto::CheckinReport {
                    outcome: proto::CheckinOutcome::Done,
                    credit: None,
                    streak: status.streak,
                    message: Some("今日已签到".to_string()),
                });
            }
            if !status.claimable {
                return Ok(proto::CheckinReport {
                    outcome: proto::CheckinOutcome::Ineligible,
                    credit: None,
                    streak: status.streak,
                    message: Some("今天不在可签到的时间窗口内".to_string()),
                });
            }
            let claim_body = methods::control_post(
                &client,
                product::SIGNIN_CLAIM_PATH,
                &credentials,
                &query,
                "签到领取",
            )
            .await?;
            Ok(match checkin::parse_claim(&claim_body)? {
                checkin::ClaimOutcome::Claimed { credit } => proto::CheckinReport {
                    outcome: proto::CheckinOutcome::Claimed,
                    credit,
                    streak: status.streak,
                    message: None,
                },
                // 状态说能领、领的时候说已领：并发或时区边界，如实报「已完成」
                checkin::ClaimOutcome::Already => proto::CheckinReport {
                    outcome: proto::CheckinOutcome::Done,
                    credit: None,
                    streak: status.streak,
                    message: Some("今日已签到".to_string()),
                },
            })
        })
    }

    /// 发起设备码授权。
    fn login_start<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        method: &'a str,
        _payload: &'a Value,
    ) -> SendFuture<'a, proto::LoginStart> {
        Box::pin(async move {
            if method == "token" {
                return Err("令牌方式请直接粘贴到输入框".to_string());
            }
            let client = crate::http::control_client(None, &ctx.env.proxy);
            let auth = oauth::start_device(&client).await?;
            let instructions = format!(
                "在打开的页面里输入代码 {} 并确认授权（{} 分钟内有效）",
                auth.user_code,
                auth.expires_in_sec / 60
            );
            let url = auth.verification_uri_complete.clone();
            let poll_interval_ms = (auth.interval_sec.max(2) as u64) * 1000;
            let flow = methods::store_flow(auth);
            Ok(proto::LoginStart {
                flow,
                url,
                instructions,
                poll_interval_ms,
                // 授权页要在系统浏览器里走官方登录（内嵌窗口会被拒）
                external_browser: true,
                allowed_hosts: vec!["minimax.cn".to_string(), "minimax.io".to_string()],
            })
        })
    }

    /// 轮询设备码授权结果。
    fn login_poll<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        flow: &'a str,
    ) -> SendFuture<'a, proto::LoginPoll> {
        Box::pin(async move {
            let Some(auth) = methods::load_flow(flow) else {
                return Ok(proto::LoginPoll::Failed {
                    message: "登录会话已过期，请重新发起登录".to_string(),
                });
            };
            let client = crate::http::control_client(None, &ctx.env.proxy);
            Ok(match oauth::poll_once(&client, &auth).await {
                oauth::PollOutcome::Granted(credentials) => {
                    methods::forget_flow(flow);
                    proto::LoginPoll::Done {
                        account: methods::normalized_from(&credentials),
                    }
                }
                // 这两个「失败」其实是「继续等」，由调用方按 interval 再问
                oauth::PollOutcome::Failed(reason) if reason == "__pending__" => {
                    proto::LoginPoll::Pending { hint: None }
                }
                oauth::PollOutcome::Failed(reason) if reason == "__slow_down__" => {
                    proto::LoginPoll::Pending {
                        hint: Some("请稍候，上游要求放慢查询频率".to_string()),
                    }
                }
                oauth::PollOutcome::Failed(message) => proto::LoginPoll::Failed { message },
                oauth::PollOutcome::Denied => {
                    methods::forget_flow(flow);
                    proto::LoginPoll::Failed {
                        message: "授权被拒绝".to_string(),
                    }
                }
                oauth::PollOutcome::Expired => {
                    methods::forget_flow(flow);
                    proto::LoginPoll::Failed {
                        message: "设备码已过期，请重新发起登录".to_string(),
                    }
                }
            })
        })
    }

    /// 取消登录（丢掉会话）。
    fn login_cancel<'a>(&'a self, _ctx: &'a PluginCtx, flow: &'a str) -> SendFuture<'a, ()> {
        Box::pin(async move {
            methods::forget_flow(flow);
            Ok(())
        })
    }
}

/// 界面上的两种登录方式（字段名按网关 `auth.methods` 的 camelCase 契约）。
///
/// ── 为什么是「粘贴令牌」+「网页登录」这两种 ─────────────────
/// 上游只接受两条路：拿 `mmoat_` 访问令牌直接打推理端点，或者走 OAuth
/// 设备码换一对新令牌。前者适合从别处导出过令牌的人，后者是正常登录。
fn login_methods() -> Value {
    json!({
        "methods": [
            {
                "methodIndex": 0,
                "type": "oauth",
                "label": "用 MiniMax 账号登录",
                "instructions": "会打开官方授权页；在页面上确认后本机自动完成登录",
                "prompts": [],
                "localOnly": false,
                "manualCallback": false,
                "callbackInput": "url"
            },
            {
                "methodIndex": 1,
                "type": "api",
                "label": "粘贴访问令牌",
                "instructions": "粘贴 mmoat_ 开头的访问令牌。没有刷新令牌时，过期后需要重新粘贴。",
                "prompts": [
                    {
                        "key": "token",
                        "type": "text",
                        "label": "访问令牌",
                        "placeholder": "mmoat_…",
                        "secret": true,
                        "optional": false
                    }
                ],
                "localOnly": false,
                "manualCallback": false,
                "callbackInput": "url"
            }
        ]
    })
}

/// 内置清单形态的目录（`remote=false`）。
fn builtin_catalog() -> proto::ModelList {
    proto::ModelList {
        models: fallback_models(),
        meta: proto::CatalogMeta {
            remote: false,
            refreshed_at: 0,
        },
    }
}

// ─── 进程内的远程目录快照 ─────────────────────────────────────
//
// `models` 读、`refresh_models` 写。宿主的一次刷新是 `models.refresh` →
// `models.list` 两个 RPC，快照让第二个不必再出网（见 `models` 的说明）。
//
// 为什么不做 TTL：目录只在用户显式刷新 / 定时任务里拉，宿主自己会按间隔
// 驱动；在这里再叠一层过期判断只会让「刚刷新过却仍读旧表」这种故障多一个
// 来源。进程重启后回到内置表，下一次刷新再填。

type CatalogSnapshot = (Vec<proto::ModelRecord>, i64);

fn catalog_cell() -> &'static Mutex<Option<CatalogSnapshot>> {
    static CELL: OnceLock<Mutex<Option<CatalogSnapshot>>> = OnceLock::new();
    CELL.get_or_init(|| Mutex::new(None))
}

fn store_catalog(models: Vec<proto::ModelRecord>) {
    let stamp = chrono::Utc::now().timestamp_millis();
    if let Ok(mut guard) = catalog_cell().lock() {
        *guard = Some((models, stamp));
    }
}

fn cached_catalog() -> Option<proto::ModelList> {
    let guard = catalog_cell().lock().ok()?;
    let (models, refreshed_at) = guard.as_ref()?;
    Some(proto::ModelList {
        models: models.clone(),
        meta: proto::CatalogMeta {
            remote: true,
            refreshed_at: *refreshed_at,
        },
    })
}

/// 拉一次远端目录并解析（不落快照 —— 由调用方决定是否采纳）。
async fn fetch_catalog(
    client: &reqwest::Client,
) -> Result<Vec<proto::ModelRecord>, String> {
    let path = format!(
        "{}?region={}&buildEnv={}",
        product::MODELS_PATH,
        product::REGION,
        product::BUILD_ENV
    );
    let response = client
        .get(format!("{}{path}", product::API_HOST))
        .timeout(std::time::Duration::from_secs(20))
        .send()
        .await
        .map_err(|error| format!("模型目录请求发不出去：{error}"))?;
    let body = methods::read_json(response, "模型目录").await?;
    Ok(parse_catalog(&body))
}

/// 兜底模型清单（远程目录拉不到时的唯一来源）。
fn fallback_models() -> Vec<proto::ModelRecord> {
    // `ModelRecord` 是 `serde_json::Value` 的别名（协议层刻意不为模型形状
    // 定结构：各家目录字段差异太大，统一成自由 JSON 由网关按需读）
    product::DEFAULT_MODELS
        .iter()
        .map(|(id, name)| json!({ "id": id, "name": name }))
        .collect()
}

/// 解析远端目录：`{providers:[{config:{models:{<id>:{…}}}}]}` → 网关认识的字段。
///
/// 键名对齐聚合层 `models::list_item` 认的那一套（`maxInputTokens` /
/// `maxOutputTokens` / `supportsImages` / `supportsReasoning` /
/// `supportsToolCall`）—— 自造键名会让界面上这一家的限额列空白，而拉取本身
/// 看起来完全正常。
///
/// 上游没给的字段**不写**（而不是写 `false`）：`supportsReasoning: false` 会被
/// 界面当成「这家一定不支持思考」，而「不知道」与「不支持」不是同一件事。
fn parse_catalog(body: &Value) -> Vec<proto::ModelRecord> {
    let mut models: Vec<proto::ModelRecord> = Vec::new();
    let providers = body
        .get("providers")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for provider in &providers {
        let Some(map) = provider
            .pointer("/config/models")
            .and_then(Value::as_object)
        else {
            continue;
        };
        for (id, info) in map {
            if id.trim().is_empty() {
                continue;
            }
            let mut record = json!({
                "id": id,
                "name": info
                    .get("name")
                    .and_then(Value::as_str)
                    .filter(|text| !text.trim().is_empty())
                    .unwrap_or(id),
            });
            let Some(fields) = record.as_object_mut() else {
                continue;
            };
            // ── 上下文窗口：取 `context_window_options` 的**最大档** ──────
            // 不能直接用 `limit.context`。实测（2026-11-06）M3 的上游目录是
            // `limit.context = 512000` 而 `context_window_options = [512000,
            // 1000000]`（1M 那档带 `context_window_option_hints.1000000 =
            // "higher_usage"`，即「用满 1M 会多算额度」，不是「不支持」）。
            //
            // 为什么这条特别重要：网关 `model_meta::fill` 对**上游已声明**的
            // `maxInputTokens` 是「岿然不动」—— 一旦这里写了 512000，
            // models.dev 那条 `context: 1048576` 就不会再被采用（`capSources`
            // 记成 upstream）。于是用户在模型页看到的上下文永久偏小一半，
            // 而且看起来像上游的真实声明，查起来会往上游找。
            let context = info
                .get("context_window_options")
                .and_then(Value::as_array)
                .map(|options| {
                    options
                        .iter()
                        .filter_map(Value::as_i64)
                        .filter(|value| *value > 0)
                        .max()
                        .unwrap_or(0)
                })
                .filter(|value| *value > 0)
                .or_else(|| info.pointer("/limit/context").and_then(Value::as_i64));
            if let Some(context) = context {
                fields.insert("maxInputTokens".to_string(), json!(context));
            }
            if let Some(output) = info.pointer("/limit/output").and_then(Value::as_i64) {
                fields.insert("maxOutputTokens".to_string(), json!(output));
            }
            if let Some(flag) = info.get("reasoning").and_then(Value::as_bool) {
                fields.insert("supportsReasoning".to_string(), json!(flag));
            }
            // ── 思考档位：**刻意不写** `efforts` / `reasoningLevels` ────────
            // 上游目录当前版本（实测 2026-11-06）没有 `effort_options` 字段，
            // 只有 `thinking_config.mode`（`switchable` / `forced_on`）与
            // `variants`（`thinking` / `none-thinking` 两套 `thinking.type`）。
            // 前者决定「能不能关思考」，后者决定「发什么 body」，都不是
            // 「档位表」。
            //
            // 档位表在网关的 models.dev 元数据里（`levels`），由
            // `model_meta::fill::normalize_levels` 补进来：只有**上游没声明**
            // 档位时才会用 models.dev 那份。这里一旦写个空数组或猜几个档位，
            // `explicit` 就为真、models.dev 直接被跳过 —— 症状正是「原来能选
            // low/medium/high，接了插件后没了」。
            //
            // `thinking_config.mode` 也不往清单里写：网关侧没有这个键的任何
            // 消费方（只有 `credit_estimate.rs` 一行注释提到过），写了也不会
            // 显示。它属于转发知识，见 `chat.rs` 的思考决策表。
            if let Some(flag) = info.get("tool_call").and_then(Value::as_bool) {
                fields.insert("supportsToolCall".to_string(), json!(flag));
            }
            // 图片能力看输入模态里有没有 `image`（上游是
            // `modalities.input: ["text","image","video"]`）
            if let Some(inputs) = info.pointer("/modalities/input").and_then(Value::as_array) {
                let vision = inputs
                    .iter()
                    .any(|item| item.as_str() == Some("image"));
                fields.insert("supportsImages".to_string(), json!(vision));
            }
            models.push(record);
        }
    }
    // 上游的 `model_order`/`whitelist` 决定展示顺序；这里按 id 排序只为
    // 让同样的输入给出同样的输出（顺序稳定，不比上游语义更聪明）
    models.sort_by(|a, b| {
        a.get("id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .cmp(b.get("id").and_then(Value::as_str).unwrap_or(""))
    });
    models
}


/// 组装规范化结果。
fn normalized(access_token: String, refresh_token: &str) -> proto::NormalizedAccount {
    // 稳定身份：上游令牌不是 JWT，解不出 uid；这里用**令牌本身的哈希前缀**
    // 做不到稳定（刷新后令牌会变，同一账号会被当成两个）。
    // 本版没有查 `/v1/api/user/info` 拿 userId 的能力（那需要一次网络往返，
    // 而 `normalize` 阶段网关允许插件出网，但本实现刻意保持纯函数），
    // 所以如实给空串 —— 网关退化成按凭证去重时会提示可能重复。
    proto::NormalizedAccount {
        secret: json!({
            "accessToken": access_token,
            "refreshToken": refresh_token,
        }),
        public: json!({ "edition": "cn" }),
        identity: String::new(),
        desktop: false,
    }
}

#[cfg(test)]
mod catalog_tests {
    use super::*;
    use serde_json::json;

    /// 远端目录的真实形状（2026-11-05 实测截取）：`providers[].config.models`
    /// 是 **map**，键才是模型 id。按数组解析会让目录恒空。
    fn live_shape() -> Value {
        json!({
            "version": "1.0",
            "ttlSeconds": 300,
            "providers": [{
                "providerId": "minimax",
                "config": {
                    "name": "MiniMax",
                    "models": {
                        "MiniMax-M3": {
                            "name": "M3",
                            "reasoning": true,
                            "tool_call": true,
                            "limit": { "context": 512000, "output": 128000 },
                            "modalities": { "input": ["text", "image", "video"], "output": ["text"] }
                        },
                        "MiniMax-M2.7": { "name": "M2.7", "reasoning": false }
                    }
                }
            }]
        })
    }

    #[test]
    fn catalog_reads_map_keyed_models() {
        let models = parse_catalog(&live_shape());
        assert_eq!(models.len(), 2, "{models:?}");
        // 排序后 M2.7 在前
        let m2 = &models[0];
        assert_eq!(m2["id"], "MiniMax-M2.7");
        assert_eq!(m2["name"], "M2.7");
        assert_eq!(m2["supportsReasoning"], false);
        // 上游没给的字段不写（「不知道」≠「不支持」）
        assert!(m2.get("supportsToolCall").is_none(), "{m2}");
        let m3 = &models[1];
        assert_eq!(m3["maxInputTokens"], 512000);
        assert_eq!(m3["maxOutputTokens"], 128000);
        assert_eq!(m3["supportsToolCall"], true);
        assert_eq!(m3["supportsImages"], true);
    }

    #[test]
    fn catalog_rejects_unknown_shape() {
        assert!(parse_catalog(&json!({ "data": [{ "id": "x" }] })).is_empty());
        assert!(parse_catalog(&json!({})).is_empty());
    }

    /// 上下文窗口取 `context_window_options` 的**最大档**，不是 `limit.context`。
    ///
    /// 现场（2026-11-06 实测）：M3 是 `limit.context = 512000` +
    /// `context_window_options = [512000, 1000000]`。写 512000 的话网关
    /// `model_meta::fill` 会把它当「上游已声明」而拒绝采用 models.dev 的
    /// 1048576，用户在模型页看到的上下文永久偏小一半。
    #[test]
    fn catalog_uses_largest_context_option() {
        let body = json!({
            "providers": [{
                "config": { "models": {
                    "MiniMax-M3": {
                        "name": "M3",
                        "limit": { "context": 512000, "output": 128000 },
                        "context_window_options": [512000, 1000000],
                        "context_window_option_hints": { "1000000": "higher_usage" }
                    }
                } }
            }]
        });
        let models = parse_catalog(&body);
        assert_eq!(models[0]["maxInputTokens"], 1000000, "{models:?}");
        assert_eq!(models[0]["maxOutputTokens"], 128000);
    }

    /// 没有 `context_window_options` 时回落 `limit.context`（老目录形态）。
    #[test]
    fn catalog_falls_back_to_limit_context() {
        let body = json!({
            "providers": [{ "config": { "models": {
                "MiniMax-M2.5": { "name": "M2.5", "limit": { "context": 204800 } }
            } } }]
        });
        assert_eq!(parse_catalog(&body)[0]["maxInputTokens"], 204800);
    }

    /// 空数组 / 全非正数时也回落 —— 不能让「有字段但没值」把窗口写成 0。
    #[test]
    fn catalog_ignores_empty_context_options() {
        for options in [json!([]), json!([0, -1])] {
            let body = json!({
                "providers": [{ "config": { "models": {
                    "M": { "limit": { "context": 131072 }, "context_window_options": options }
                } } }]
            });
            assert_eq!(parse_catalog(&body)[0]["maxInputTokens"], 131072, "{body}");
        }
    }

    /// **不写档位**：上游没有 `effort_options`，档位由网关的 models.dev 补。
    /// 这里一旦写出 `efforts`（哪怕是空数组），网关 `normalize_levels` 的
    /// `explicit` 就为真、models.dev 被跳过 —— 症状是「接了插件后档位没了」。
    #[test]
    fn catalog_never_declares_efforts() {
        let models = parse_catalog(&live_shape());
        for model in &models {
            for key in ["efforts", "reasoningEfforts", "reasoningLevels"] {
                assert!(model.get(key).is_none(), "{key} 不该由插件声明：{model}");
            }
        }
    }
}
