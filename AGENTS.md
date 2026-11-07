# 本地插件维护约束

## 工作区与包身份

- 工作区：`D:\Ai\api\agent2api-dev\Agent2Providers`；原 `agent2providers-src` 的本地代码、Git 历史和 MiniMax 改动是迁移基准，继续在此添加自定义提供商。
- 开发分支：`custom/agent2providers`；`origin` 为个人 Fork `https://github.com/pclfly/Agent2Providers.git`，`upstream` 为官方 `https://github.com/ProvidersPlugin/Agent2Providers.git`；默认推送目标仅 `origin`。
- 2026-11-07 已在登录的 `pclfly` 账号创建个人 Fork，核实来源为 `ProvidersPlugin/Agent2Providers`、网页所有权及 `git ls-remote origin` 读取成功。未执行命令行推送认证测试；网页登录不等于 Git 凭据就绪，首次推送前重新核实 Git 认证与权限。
- 「提供商增强（自定义）」继续由 `scripts/pack-subset.mjs` 输出；保持现有自定义包 id `agent2api-custom`，一个包可以包含多家。新增 provider 时核对实现注册、Cargo feature、包清单、必要的 feature/id 映射与相关测试。
- 不因重命名目录而改变 provider id、包 id、协议、版本或官方更新源；不覆盖正在使用的插件 EXE，不自动安装至运行区。

## 同步与保留

- 仅用户明确下达「同步 agent2api 官方更新」并明确把本插件仓纳入范围时，按用户级 `sync-upstream-agent2api` Skill 执行；默认该口令只涵盖网关仓。平时不主动 fetch/pull/merge/commit/push。
- 先检查工作区、分支、远程、提交关系与敏感文件；有未处理代码时先提交并推送个人 custom 分支作为合并前备份。失败即停止，不带着未保护改动合并。
- 合并前从当前 custom 分支建立 `backup/custom-baseline-YYYYMMDD`，重名追加序号且不覆盖，记录完整 hash。随后获取并 merge `upstream/main`，不用 rebase、不改写历史、不强推。
- 保留自定义功能并吸收官方更新；无法安全判断的冲突暂停询问。不用整文件 ours/theirs 代替逐项核对。
- 检查实际 crate 名后运行受影响插件 crate 的 `cargo check` / `cargo test --locked`，必要时做协议与宿主集成验证。编译成功不等于 provider 能力验证通过。验证失败不推送合并结果，除非用户另行明确要求；通过后只推 `origin/custom/agent2providers`。
- 最终逐项报告回滚点/hash、合并提交、冲突、自定义能力、测试通过/失败/跳过及合并前备份和合并后两阶段推送结果。
- 不默认推 upstream、main/beta 或 tag，不自动改版本、CI、签名密钥或发 Release；不因上游发版规范而切离个人 custom 分支。
- 保留所有已有未提交改动、旧分支、stash、`target`、`dist` 和本地备份。不得自动清理旧目录或缓存，不使用 hard reset。

## 与网关及运行区的边界

- 网关工作区：`D:\Ai\api\agent2api-dev\Agent2API`。网关 Cargo 命令必须显式选择 `-p agent2api-server`，不借插件联调触发 Tauri/手机端构建。
- 运行目录：`D:\Ai\api\agent2api-plugin-data`，不迁移、不提交数据库、密钥或账号凭据。测试使用独立数据目录和空闲端口。
- 旧工作区 `D:\Ai\api\agent2api`、迁移前源码目录和同级退役说明目录不是开发或同步备用目标。
- 本次迁移未运行官方同步，也未重新验证历史测试数字；每次同步重新检查基线，不沿用示例的通过数。
