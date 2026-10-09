# EIAM 四维优化分级问题清单

> 审计目标：`github.com/Havens-blog/e-iam`（`D:\Haven\eiam`，企业级多租户 IAM 平台）
> 四维：①工程体检与工具链　②架构与代码质量　③性能　④安全
> 工具链：`go1.26.9 windows/amd64`，`gofmt / go vet / go test -race / govulncheck / go test -bench`
> 说明：本清单为只读审计产出，附 file:line 证据。每条标注【维度】【级别】【状态】。

---

## 0. 总览

| 维度 | P0 | P1 | P2 | P3 | 宏观结论 |
|------|----|----|----|----|----------|
| ①工程/工具链 | 0 | 0 | — | — | gofmt/vet/test 全绿基线已建立；生成链存在跨平台路径漂移与 CI 缺失，**已修复** |
| ②架构/代码质量 | 0 | 1 | 6 | 5 | 宏观分层健康，Domain/Transport/Service/pkg 依赖方向全部通过；问题集中在错误哨兵泄漏与命名一致性。②-P1-1/②-P2-1/②-P2-2/②-P2-4/②-P2-5/②-P2-6 **已修复**；I 前缀(pkg 对外契约) P2-3 延后 |
| ③性能 | 1 | 3 | 3 | 2 | 缓存/批处理基础设施成熟；PBAC 求值热路径重复校验是确定性浪费。③-P0-1/P1-1/P1-2/P1-3/P2-1/P2-2/P2-3 **全部已修复**；P3 择期 |
| ④安全 | 0 | 3 | 4 | 4 | 近期硬化项（Fail-Closed/AK-SK 恒定时间/JWT 锁定/CORS 互斥/permission fail-closed）均有效；残留明文凭证、审计端点未鉴权、跨租户密钥操纵。④-P1-1/P1-2/P1-3/P2-1/P2-2/P2-3 **已修复**；间接依赖已升级；P2-4 运维处置 |

**依赖漏洞**：`govulncheck` 调用链 0 可利用；5 个间接依赖漏洞均未被调用，可低风险升级（见 ④依赖小节）。

---

## ① 工程体检与工具链

基线（go1.26.9）：`go build ./...` ✅　`go vet ./...` ✅　`go test ./...` ✅

### ①-1【P1·已修复】gofmt 工作区 CRLF 失真
- 37 个文件 gofmt 违规（结构体标签对齐/导入排序/`//go:generate` 前补 `//`），叠加工作区 CRLF 导致 `gofmt -l` 报 330 文件。
- 修复：`gofmt -w` 规范化 + `.gitattributes eol=lf` 落实，`gofmt -l` 现为 0。

### ①-2【P1·已修复】生成链跨平台路径漂移（permgen）
- `pkg/gen/capability/parser.go:30` `filepath.Walk` 在 Windows 产出反斜杠源码路径写入 `docs/permissions.md`，与 Linux CI 产物 diff，破坏生成链一致性守护。
- 修复：Walk 回调顶部 `filepath.ToSlash(path)` 统一正斜杠。

### ①-3【P1·已修复】生成链产物与提交不同步
- `ioc/wire_gen.go` var 命名漂移（`reporter→v3`）；`go.sum` 缺 wire CLI 依赖（subcommands/difflib）；`docs/permissions.md`（idp handler 行号迁移）；`api/docs/swagger.json`+`index.html`（新增路由端点，已验证 swaggergen 确定性）。
- 修复：重生成并提交；`go mod tidy` 一致化。

### ①-4【P1·已修复】mockgen 工具链版本失配
- 本机 `mockgen` 二进制为 go1.24.1 构建，无法解析 go1.26 源（`package requires newer Go version go1.26`）。根因：`go install X@v` 在空 go.mod 下回落到基础工具链。
- 修复：`GOTOOLCHAIN=go1.26.9 go install go.uber.org/mock/mockgen@v0.6.0`；CI `ci.yml` 显式锁定 `GOTOOLCHAIN=go1.26.9`。

### ①-5【P1·已修复】CI 缺失与 docker-publish 触发过宽
- 原仅有 `docker-publish.yml`（`branches:["**"]` 每分支打镜像+推送），无 Go fmt/vet/test/生成链护栏。
- 修复：新增 `.github/workflows/ci.yml`（gofmt 零违规 + go vet + `go test -race` + 生成链一致性守护 protoc/wire/mock/permgen/swaggergen 零 diff）；docker-publish 触发收紧到 `main` + concurrency。

---

## ② 架构与代码质量

**正面发现（保持）**：Domain 零持久化/Transport 依赖；Transport 未直连 DAO；Service 未反向依赖 Transport；pkg 未反向依赖 internal/；哨兵错误集中 `internal/errs/error.go`；goroutine 均有退出机制；HTTP body/reader 均 defer Close；VO↔Domain 转换集中在 `mapper.go`。

### ②-P1-1【P1】gRPC Transport 依赖 GORM（错误哨兵泄漏）
- `internal/grpc/user.go:16` import `gorm.io/gorm`；`:133,143` `errors.Is(err, gorm.ErrRecordNotFound)`。
- 根因：`internal/service/user/service.go:201-207` GetById/GetByUsername 直接转发 repo 错误未翻译；`internal/repository/user.go:176,185` 未把 not-found 翻译为领域哨兵，导致 GORM 错误穿透到 Transport。
- 违反 Transport 严禁依赖持久化框架；修复：新增 `errs.ErrUserNotFound`，DAO/Repo 翻译 `gorm.ErrRecordNotFound`，移除 grpc 的 gorm import。

### ②-P2-1【P2】Repository 层依赖 GORM 错误哨兵
- `internal/repository/user.go:15,176,185`、`resource.go:14,176` import gorm 仅判 ErrRecordNotFound。属严格分层解读下的违规（GORM 归 DAO）。随 ②-P1-1 一并剥离。

### ②-P2-2【P2·已修复】internal/ 9 个导出接口缺 `I` 前缀
- 已补 I 前缀：`Crypto→ICrypto`、`CredentialProvider→ICredentialProvider`、`PermissionProvider→IPermissionProvider`（仅 internal）、`SubjectProvider→ISubjectProvider`、`RedisearchLdapUserCache→IRedisearchLdapUserCache`、`OidcService→IOidcService`、`AuthStrategy→IAuthStrategy`、`AuthorizationProvider→IAuthorizationProvider`、`Engine→IEngine`（同时消除与 `gin.Engine` 同名混淆）。mock/wire 已重生成。

### ②-P2-3【P2·暂缓】pkg/ 9 个导出接口缺 `I` 前缀
- `pkg/certx/source.go:11 Source`、`pkg/sorter/sorter.go:15 Sortable`、`pkg/migration/types.go:44 Migrator`、`pkg/web/capability/model.go:84 PermissionProvider,:89 MenuProvider,:129 Reporter`、`pkg/web/capability/syncer/syncer.go:16 Syncer`。pkg 为对外契约，重命名影响下游，需评估兼容窗口。`PrivateKey/PublicKey`（类型约束接口）建议保留为例外。

### ②-P2-4【P2·已修复】DAO 分页样板重复（18 处）
- 新增 `internal/repository/dao/paginate.go`：`Paginate(offset, limit)` GORM Scope，统一封装 `Offset/Limit` 计算。19 处 DAO 查询（含 1 处 `Limit().Offset()` 反序变体）收敛为 `.Scopes(Paginate(offset, limit))`，消除样板重复。

### ②-P2-5【P2·已修复】`PermissionProvider` 双处定义
- 经 ②-P2-2 重命名后，internal 版 `domain.PermissionProvider → IPermissionProvider`，pkg 版 `capability.PermissionProvider` 保留原名为对外契约，两者不再同名冲突。

### ②-P2-6【P2·已修复】service ~80 处裸 `return err` 未附加上下文
- 已为 8 个 service 文件（user/tenant/permission/policy/role/department/group/idp-application）中 63 处转发不透明 repo/DAO 错误的裸 `return err` 补 `fmt.Errorf("...: %w", err)` 上下文；errgroup 闭包重构为 `if err != nil { return fmt.Errorf(...) }; return nil` 区分失败 goroutine。豁免 70 处转发领域哨兵/service 方法的点。`%w` 保留错误链，`errors.Is` 断言不受影响。

### ②-P3（5 项，极低风险，可选）
- P3-1 错误双重表达：`internal/errs` 与各 web 包 `errs.go` 并存（如 `ErrRoleCycleInheritance`），建议集中映射表。
- P3-2 fire-and-forget 审计协程静默吞错（`idp/audit.go:27`、`user/coordinator.go:206,237`），实现质量高（recover+timeout+提前提取 clientIP/UA），建议失败至少 elog Warn。
- P3-3 discovery 主同步路径 `context.Background()`（`service.go:66`），复核是否应透传调用方 ctx。
- P3-4 per-web-package `errs.go` 样板，可生成器化。
- P3-5 `permission.go:58` 构造期 panic 可改返回 error。

---

## ③ 性能

基准：`BenchmarkOPA_Decide_Simple` 73812 ns/op 470 allocs/op；`BenchmarkOPA_Decide_ComplexPBAC` 124117 ns/op 613 allocs/op。OPA Rego 引擎固有成本不纳入低风险优化。

### ③-P0-1【P0·最高优先·已修复】PBAC 求值热路径重复全树校验
- `pkg/pbac/condition.go:286 EvaluateCondition→ValidateCondition(:159)`；`:307 PartialEvaluateAccessScope→ValidateAccessScope(:176)`；`pkg/pbac/gormx/filter.go:55-60 Compile` 再两次校验。策略写入 `policy.go:109 ValidatePolicyExpressions` 已强校验，求值路径可删校验直接走 `evaluateNode`。零行为变更，预计复杂 PBAC allocs/op ↓10-20%。

### ③-P1-1【P1·已修复】CheckAPIDecision 串行 5+ 次 DB/Redis 往返
- `internal/service/permission/permission.go:112`；`getEffectivePolicies`（:391 `GetAttachedBySubjects` 双 DB + `ListByIncludeCodes` DB）每请求无缓存。建议按 `(tenant_id,username)` Redis 短缓存 + 变更点失效。中等改动，建议独立 PR。

### ③-P1-2【P1·已修复】ListAllMenus 全表扫描无缓存
- `internal/service/resource/resource.go:68→dao:155`；`GetAuthorizedMenus`(:249)/`GetMenusByURNs`(:491) 每次全表+内存过滤，菜单元数据极低频变更。`resourceCache` 缺菜单全量缓存。建议加 `Get/Set/InvalidateAllMenus`，`SyncMenus` 失效。

### ③-P1-3【P1·已修复】PhysicalClearService 全表扫描后内存过滤
- `internal/repository/permission.go:403` `ListAll` 后 `if p.Service==service && p.Source==source`。建议 DAO 加 `ListByServiceAndSource` 走索引。

### ③-P2-1【P2·已修复】sortActions 每次重编译 4 正则
- `internal/service/permission/permission.go:646,:654-657`，`toGroupNodes`(:616) 每节点调一次。提为包级 var。

### ③-P2-2【P2·已修复】GetMenu 走 ListAllMenus 全表+线性
- `internal/repository/resource.go:270` 单条主键却全表+O(n)。建议 DAO `FindMenuByID` 主键点查。

### ③-P2-3【P2·已修复】pkg/pbac 无 Benchmark
- 求值核心缺基线，无法量化 P0-1 收益。建议补 `EvaluateCondition`/`PartialEvaluateAccessScope`/`Compile` bench。

### ③-P3（2 项）
- P3-1 `reflect.ValueOf(ctx.Handler()).Pointer()`+两层 RLock（`permission.go:36`），微优化非瓶颈。
- P3-2 OPA Eval 470 allocs 属 Rego 固有成本，PreparedEvalQuery 已缓存未每请求重编译。

---

## ④ 安全

**已确认硬化有效（不重复报告）**：租户插件四路 Fail-Closed + 双通道提权；业务 DAO 无 Raw/Exec（仅 migration/Redis pipe）；IgnoreTenantContext 调用点正当；origin_tenant_id 超管覆写正确拦截；invitation Accept 注入 tenant_id 后 IncrUsedCount；SQL 全参数化、Order 全静态、quoteIdentifier 正确；无 os/exec；Rego embed 编译期固定无注入；JWT 算法锁定（OIDC RSA/gRPC HS256）；OIDC redirect_uri/state/nonce 严格；CORS 通配+凭证互斥；permission 中间件 fail-closed 正确；discovery 端点默认鉴权；审计豁免仅 `/api/audit/batch`；SAML 签名+ACS 白名单+解压炸弹防护。

### ④-P1-1【P1·最高优先·已修复】租户 SecretKey 与资产发现令牌明文落库
- `internal/repository/dao/tenant_key.go:34` `SecretKey string` 明文；`tenant_key.go:32-38` Create 直拷；`internal/service/tenant/tenant_key.go:86` 与明文 ConstantTimeCompare；`internal/service/discovery/token.go:67-75,83-104` `AccessKey==SecretKey==token` 单值明文且 VerifyToken 不校验密钥。对照 `application.go:18 ClientSecretHash` 已正确存哈希。
- 攻击：DB 只读泄露→全量租户 AK/SK + 全部资产发现令牌。
- 修复：SK 存 KDF 哈希（argon2id/pbkdf2/sha256+salt），VerifyKey 比哈希；令牌存 `HMAC(server_key, token)`；一次性迁移回写哈希。

### ④-P1-2【P1·已修复】审计批量上报端点完全未鉴权（审计投毒）
- `internal/web/audit/handler.go:30-32` `POST /api/audit/batch` 注册在 PublicRoutes，`ioc/web.go:51-60` 在 CheckLoginMiddleware(:63) 之前，无 Token/签名；`:35-57` Records 全攻击者可控；消费端 `consumer.go:158` IgnoreTenantContext 跨租户落库。
- 攻击：审计投毒/栽赃/DoS/潜在存储 XSS。
- 修复：复用 discovery `eiam_sct_` Token 或 mTLS/内网签名，校验 `req.Service` 与 Token 绑定；AfterState 字段长度上限+净化；前端转义。

### ④-P1-3【P1·已修复】租户密钥状态变更缺归属校验（跨租户密钥操纵）
- `internal/repository/dao/tenant_key.go:32` 整表 `eiam:"ignore"`；`:65-69` `UpdateStatus` 仅 `Where("id = ?", id)` 无 tenant_id 过滤。
- 攻击：租户 A 枚举 key ID 禁用/启用租户 B 密钥（DoS/配合社工）。
- 修复：DAO `UpdateStatus`/`ListByTenantID` 补 `AND tenant_id = ?`，或 service 先 FindByID 校验归属。

### ④-P2-1【P2·已修复】会话 Cookie 未设 SameSite
- `ioc/session.go:78-87` `cookie.TokenCarrier` 无 SameSite；`:50-55` 结构体无字段。CSRF 拼留面。修复：加 SameSite 配置（默认 Lax）。

### ④-P2-2【P2·已修复】OIDC Logout 开放重定向
- `internal/web/idp/handler.go:326-340` `post_logout_redirect_uri` 直接 302 无白名单。修复：维护白名单或要求 id_token_hint。

### ④-P2-3【P2·已修复】gRPC Verify 凭证预言机（鉴权默认可选）
- `internal/grpcx/server.go:25,73-78` AuthToken 为空不挂拦截器；`internal/grpc/tenant.go:20-28` Verify 暴露 VerifyKey。修复：`auth_token` 为空时启动失败；Verify 加调用方校验/限流。

### ④-P2-4【P2·已修复+运维】本地 config/config.yaml 泄露真实基础设施凭证
- 代码侧 fail-fast 拒绝弱密钥：新增 `internal/cryptox/secrets.go` 的 `ValidateSecret`，校验 `session_encrypted_key`/`identity.encryption_key`/`grpc.server.eiam.auth_token` 三处——空值、长度 <32 字节、示例占位符（`your-grpc-auth-token`/`your-session-encrypt-key`/`your-identity-encryption-key`/`changeme`/`123456`）一律拒绝启动。**运维侧仍需轮换 config.yaml 中已落盘的真实凭证为强随机值**（代码侧已阻止弱值进入运行时）。

### ④-P3（4 项）
- P3-1【已修复】LDAP `InsecureSkipVerify`（`pkg/ldapx/client.go`）：保留可配逃生舱（内网自签证书），但 ldaps 连接关闭校验时记 elog Warn 告警，让绕过可见可审计；登录路径已 EscapeFilter 无注入。
- P3-2【已修复】JWT kid 感知验签（`idp/oidc/key.go`）：SignJWT 已设 kid；VerifyJWT 改为从 token 头部取 kid 经 KeyByID 定位公钥校验（非固定当前公钥），为密钥轮换（多公钥并存、旧 kid 宽限期验签）预留能力。完整集群轮换（缓存多密钥历史 + TTL 宽限）需独立功能迭代。
- P3-3【评估·上游阻断】go-jose v3 v3.0.5 间接依赖停维护，但经 `coreos/go-oidc/v3` 间接引入（`internal/service/identity_source` OIDC 客户端用），上游未迁移 v4，本仓库无法单方面移除；直接 OIDC Provider 已用 v4。待上游迁移后收敛。
- P3-4【评估·前端处置】审计 AfterState 自由文本日志注入/存储 XSS 拼面：服务端已做长度截断（≤4096，batch ④ `sanitizeAuditText`），审计日志经 JSON API 返回（无服务端 HTML 渲染，JSON 字符串不被浏览器执行）；存储 XSS 实际风险在前端审计查看页渲染 AfterState 时须强制转义，属前端职责。

### ④-依赖【govulncheck·已升级】
调用链 0 可利用漏洞。间接依赖已低风险升级：etcd client v3.6.11→v3.6.14、klauspost/compress v1.18.4→v1.18.7、Azure/go-ntlmssp→v0.1.1、valyala/fasthttp v1.45.0→v1.70.0（连带 andybalholm/brotli v1.2.0→v1.2.1）；`golang.org/x/crypto v0.57.0` 暂无修复版。`golang-jwt/jwt/v4 v4.5.2` 已是 CVE-2025-30204 修复版且使用安全；建议长期收敛到单一 v5。

---

## 本批落地范围（修复→验证→提交闭环）

- **批次① 已提交**：①-1~①-5 全部（gofmt、生成链本地化、CI 护栏）。
- **批次② 已提交**：②-P1-1（gRPC gorm 剥离 + errs.ErrUserNotFound）、②-P2-1（Repo gorm 剥离）、②-P2-2（9 internal 接口 I 前缀 + mock/wire 重生成）、②-P2-4（DAO 分页助手 Paginate Scope，19 处样板收敛）。暂缓 P2-3(pkg 对外契约)/P2-5/P2-6/P3。
- **批次③ 已提交**：③-P0-1（PBAC 移除重复校验，bench 基线 EvaluateCondition_Complex 977→622 ns/op ↓36%、PartialEvaluateAccessScope 208→154 ↓26%）、③-P2-1（正则包级 var）、③-P1-3（PhysicalClearService DB 过滤）、③-P1-2（ListAllMenus Redis 缓存 + 变更失效）、③-P2-2（GetMenu 主键点查）、③-P2-3（pbac bench 基线）、③-P1-1（getEffectivePolicies Redis 短缓存 30s+jitter，AssignRolesToUser/RemoveRolesFromUser 即时失效；跨服务变更走 TTL 兜底）。P3 择期。
- **批次④ 已提交**：permission.go fail-closed、④-P1-1（凭证 SHA-256 哈希存储 + 双轨兼容迁移）、④-P1-2（审计端点 fail-closed 令牌鉴权 + 自由文本长度收敛）、④-P1-3（UpdateStatus tenant_id 归属过滤）、④-P2-1（SameSite=Lax）、④-P2-2（Logout 同源校验 + 白名单精确比对）、④-P2-3（gRPC auth_token 强制非空）、间接依赖升级（etcd v3.6.14、klauspost v1.18.7、go-ntlmssp v0.1.1、fasthttp v1.70.0）。P2-4 运维处置、P3 择期。

**验证闭环**：`gofmt -l` 0；`go build ./...` ✅；`go vet ./...` ✅；`go test ./...` ✅；生成链一致性 `go generate ./...` 零 diff。`go test -race ./...` 由 CI（Linux，gcc 可用）在 PR 时执行；本机 Windows 无 C 编译器，无法本地构建 cgo/race。
