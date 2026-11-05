//! MiniMax Code（中国版）产品常量：主机 / 端点 / 兜底模型表。
//!
//! ── 数据来源（沿用网关侧实现，全部实测或 asar 直读）────────────
//!   - 主机：asar `@mavis/config/dist/config.js` 的 `PRESET_BASE_URLS['cn-prod']`；
//!   - OAuth 端点：asar `@mavis/oauth-core/dist/endpoint-config.js`；
//!   - `clientId` / `scope` / `audience`：`~/.minimax/auth/prod/cn/mcode-public/auth.json`
//!     与 asar `contracts.js`；
//!   - 兜底模型表：2026-09-28 实测 `GET /mavis/api/v1/models?region=cn&buildEnv=prod`。
//!
//! ── 只有中国版 ──────────────────────────────────────────────
//! 上游两地的账号体系不通用（`account.minimax.cn` vs 国际站），国际版要另立
//! provider（`minimax-intl`）—— 不要往本家塞 region 字段。

/// 账号与 OAuth 主机。
pub const ACCOUNT_HOST: &str = "https://account.minimax.cn";
/// API 主机（目录 / 签到 / 积分 / 推理）。
pub const API_HOST: &str = "https://agent.minimax.cn";
/// 区域（目录查询参数）。
pub const REGION: &str = "cn";
/// 构建环境（目录查询参数）。
pub const BUILD_ENV: &str = "prod";
/// OAuth client_id（官方常量）。
pub const CLIENT_ID: &str = "mcode-public";
/// OAuth audience（asar `contracts.js` 的 `MCODE_OAUTH_AUDIENCE`）。
pub const AUDIENCE: &str = "agent-backend";
/// OAuth scope（凭据校验要求必须含它，否则 `invalid_token_response`）。
pub const SCOPE: &str = "agent.default";

// ── 端点路径 ──

/// OAuth 设备码申请。
pub const DEVICE_CODE_PATH: &str = "/oauth2/device/code";
/// OAuth 令牌（轮询与续期共用）。
pub const TOKEN_PATH: &str = "/oauth2/token";
/// 远端模型目录（需 `?region=&buildEnv=`）。
pub const MODELS_PATH: &str = "/mavis/api/v1/models";
/// 推理路径（**Anthropic Messages** 协议）。
pub const INFER_PATH: &str = "/mavis/api/v1/llm/v1/messages";
/// 签到状态（必须带 `?timezone_id=`）。
pub const SIGNIN_STATUS_PATH: &str = "/minimax-cloud/api/v1/signin/status";
/// 签到领取（必须带 `?timezone_id=`）。
pub const SIGNIN_CLAIM_PATH: &str = "/minimax-cloud/api/v1/signin/claim";
/// 积分明细。
pub const CREDIT_DETAILS_PATH: &str = "/minimax-cloud/api/v1/credit/details";
/// Anthropic Messages 的版本头（上游按它选响应形态）。
pub const ANTHROPIC_VERSION: &str = "2023-06-01";

/// 凭据前缀：访问令牌与刷新令牌各一种，**不是 JWT**（无法从串内解析过期）。
pub const ACCESS_PREFIX: &str = "mmoat_";
pub const REFRESH_PREFIX: &str = "mmort_";

/// 兜底模型表（远程目录拉不到时用它）。
///
/// 只列实测存在且可推理的模型；`MiniMax-M2.7` 系是 forced_on（不发思考字段），
/// `MiniMax-M3` 系必须显式发 `adaptive`，见 `chat.rs` 的思考决策表。
pub const DEFAULT_MODELS: &[(&str, &str)] = &[
    ("MiniMax-M3", "MiniMax-M3"),
    ("MiniMax-M2.7", "MiniMax-M2.7"),
    ("MiniMax-M2.5", "MiniMax-M2.5"),
];

/// 必须显式发 `thinking: {type: adaptive}` 的模型前缀。
///
/// ⚠️ 实测：M3.1 不发 `thinking` 直接 400；M3 不发则默认「不思考」（两轮各
/// 0 字符）。所以这一族开思考**必须**显式声明。
pub const ADAPTIVE_ONLY_PREFIX: &str = "MiniMax-M3";
