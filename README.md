# binary-static-analyzer-go

本地运行的二进制静态分析与检出工具链：把不同容器格式的可执行文件解析成统一结构模型，
按**可版本化的规则集**做规则匹配，并支持多目标并发扫描与结果缓存。所有结论都可复现：
同样的样本内容 + 同样的规则集版本 ⇒ 同样的判定结果。

无第三方依赖，仅使用 Go 标准库；要求 Go 1.25+。

## 目录结构

| 路径 | 职责 |
| --- | --- |
| `internal/binary` | 统一结构模型；手写的 ELF / PE / Mach-O 解析器与可区分的解析错误 |
| `internal/rules` | 规则集模型、JSON 加载/校验、内容哈希、规则匹配引擎 |
| `internal/scan` | 并发调度、单飞合并（singleflight）、缓存、资源上限与超时语义 |
| `cmd/binsa` | 命令行入口，输出 JSON 报告 |
| `examples/rules.json` | 示例规则集 |

## 快速开始

```bash
go build ./...
go test -race ./...

# 用示例规则扫描一个或多个文件
go run ./cmd/binsa -rules examples/rules.json -pretty /bin/true /bin/ls
```

输出是一段 JSON，包含规则集哈希和每个目标的结论；退出码：

- `0`：所有目标解析成功（可能仍有 findings，findings 本身不代表失败）
- `1`：一个或多个目标解析失败 / 被拒绝 / 超时终止
- `2`：用法或配置错误（参数错误、规则集无法读取/编译、文件无法读取等）

## 支持的格式

解析器**不依赖 `debug/elf` 等系统库**，而是手写头部与节表解析，每个字段都做边界检查，
因此截断、损坏、非法字段都会返回结构化错误而不是 panic。

| 格式 | 支持内容 | 不支持 / 明确拒绝 |
| --- | --- | --- |
| ELF | ELF32/ELF64，大小端；e_machine 支持 x86、x86-64、ARM、ARM64；文件类型（可执行/共享库/目标/core）；入口点；全部节表（名称、地址、偏移、大小、rwx 权限、原始 flags/type） | 扩展节编号 SHN_XINDEX；未知 e_machine 报 `unsupported_variant` |
| PE | PE32/PE32+（由 Optional Header Magic 判定）；Machine 支持 i386/AMD64/ARM/ARM64；DLL/EXE/OBJ 类型；入口 RVA；COFF 节表（含 `/nnn` 长节名） | 未知 Machine / Optional Magic 报 `unsupported_variant` |
| Mach-O | 32/64 位 thin 文件、大小端；LC_SEGMENT/LC_SEGMENT_64 的节（名称、地址、偏移、大小、由 initprot 推出的权限，zerofill 节做豁免）；cputype 支持 x86/x86_64/ARM/ARM64 | **fat/universal 容器**明确报 `unsupported_variant`（请先拆出 thin 成员）；LC_UNIXTHREAD/LC_MAIN 入口点不解析（EntryPoint=0） |

### 解析错误分类

错误类型 `binary.Error`（可 `errors.As` 取出），并同时可通过哨兵错误 `errors.Is` 判别：

| `Kind` | 哨兵 | 含义 |
| --- | --- | --- |
| `unsupported_format` | `binary.ErrUnsupportedFormat` | 魔数无法识别 / 输入太短 |
| `unsupported_variant` | `binary.ErrUnsupportedVariant` | 格式可识别但变体不支持（未知机器字、PE Magic、fat Mach-O 等） |
| `truncated` | `binary.ErrTruncated` | 头部/表结构/声明范围超出文件实际长度 |
| `corrupt_structure` | `binary.ErrCorrupt` | 字段之间互相矛盾、节范围越界、字符串表/名称越界等 |
| `invalid_field` | `binary.ErrInvalidField` | 字段值非法（ELF class/data/version、PE 签名、Mach-O magic 等） |

错误中带有 `Format / Offset / Field / Msg`，扫描结果里的 `error` 对象保留这些字段，
因此“截断”和“结构损坏”和“非法字段”是可区分的，而不是被静默跳过。

## 规则模型

规则集是一个 JSON 文档（见 `examples/rules.json`）：

```json
{
  "id": "example-rules",
  "version": "2026.09.1",
  "created_at": "2026-09-28T00:00:00Z",
  "rules": [
    {"id":"SEC-WRITE-EXEC","version":"1","name":"...",
     "severity":"critical","target":"section_perm","section":"*",
     "op":"contains_all","value":"wx"}
  ]
}
```

- 规则集必须有非空 `id` / `version`；规则必须有唯一 `id`、非空 `version`、合法 `severity`。
- `severity`：`info|low|medium|high|critical`。
- 加载时做严格校验（未知字段拒绝；非法 target/op/value、坏正则、重复规则 id 等返回
  `*rules.RuleError`，**构造扫描器即失败**，不会带着坏规则运行）。

### Target / Op 一览

| Target | 允许的 op | value 含义 |
| --- | --- | --- |
| `entrypoint` | `hex_equals` | `0x` 前缀的十六进制入口地址 |
| `format` | `equals` | `elf` / `pe` / `macho` |
| `section_name` | `equals` / `glob` | 精确节名或 `filepath.Match` 的 glob |
| `section_perm` | `contains_all` | `r`/`w`/`x` 的组合，如 `wx`；可用 `section` 限定节 |
| `section_content` | `contains` / `regex` | 在匹配 `section` glob 的节内做字面量或 RE2 正则匹配 |
| `file_content` | `contains` / `regex` | 在整个输入文件内匹配 |

每条命中（`Finding`）都带有：规则 id 与规则版本、严重级、命中 `location`
（节名 + 文件相对偏移 + 长度）、`matched` 片段，以及人类可读的 `basis` 判定依据
（例如 `section ".data": bytes contains "SECRET" at file offset 67`）。

### 可复现性与规则版本切换

- 每个规则集有一个 **SHA-256 内容哈希** `Hash()`，计算范围仅包含 `id`、`version`
  和全部规则字段（按数组顺序规范化为 JSON）。`created_at` 只是信息字段，**不参与哈希**。
- 扫描结果中固定记录 `rule_set_id / rule_set_version / rule_set_hash`。
- 规则升级后，新规则集哈希不同，历史样本不会命中旧缓存；只要继续加载旧版本规则集，
  同样的样本必然得到完全一致的历史结论（严重级、位置、basis 都逐字段一致）。
- 匹配结果顺序确定：按规则数组顺序、节索引顺序产生；正则使用 Go RE2（线性时间，无回溯）。

## 并发与缓存语义

`scan.Config`：

| 字段 | 默认值 | 语义 |
| --- | --- | --- |
| `Concurrency` | 4 | 同一批次最多同时评估的目标数（信号量限流） |
| `MaxFileSize` | 256 MiB | 超过大小的目标**同步拒绝**，状态 `rejected`，`error.kind=file_too_large` |
| `MaxTargets` | 10000 | 批次目标数超限**整批同步拒绝**，每个位置返回 `rejected/too_many_targets`，不启动任何解析 |
| `Timeout` | 0（不限） | 单目标评估墙钟超时；超时返回终态 `terminated`，`error.kind=timeout`，不会挂住，也不会吞错 |
| `Cache` | nil（关闭） | 并发安全的内存缓存；传 `scan.NewMemoryCache()` 启用 |

保证：

- **顺序稳定**：`ScanBatch` 的返回切片与输入目标一一对应、位置不变；
  并发结果与逐个 `Scan` 完全一致（状态、findings、basis）。测试中多轮随机并发反复比对。
- **缓存复用**：缓存键为 `<rule-set-hash>:<content-sha256>`（无规则时前缀 `no-rules:`）。
  相同内容（与文件名无关）在相同规则集下复用同一份结论，`cached=true`；
  规则版本变化时键不同，互不污染。
- **单飞合并**：同一批次中多个相同内容目标并发提交时，底层只解析/评估一次，
  两个结果共享结论；它们不标记为 cache hit（没有读预先存在的缓存），顺序扫描同一内容
  才会标记 `cached=true`。
- **只缓存内容决定性结论**：`ok` 与 `parse_failed` 入缓存；`timeout/canceled/panic`
  等资源相关结论**绝不入缓存**，避免“超时一次、永久超时”。
- **健壮性**：任何解析器/规则 panic 都在目标边界被 recover，变成
  `internal_error` 结论，不会杀死 worker goroutine。

`Timeout=0` 时仍可通过传入的 `context.Context` 做整体取消；取消同样得到
`terminated/canceled` 终态。

## 验证方法

```bash
# 全部单元测试（含畸形/截断样本、规则版本切换、并发顺序、缓存、上限与超时）
go test ./...

# 竞态检测（强烈建议）
go test -race ./...

# 覆盖率
go test -cover ./internal/...

# 手工验证 CLI
go run ./cmd/binsa -rules examples/rules.json -pretty /bin/true /bin/ls
printf 'MZ' > /tmp/trunc.bin
go run ./cmd/binsa /tmp/trunc.bin; echo "exit=$?"   # 1，error.kind=truncated
```

测试夹具均在测试代码内**程序化构造**（最小 ELF64/PE32+/Mach-O64），
并对夹具做定点字节破坏以覆盖：ELF 坏 class、未知 machine、截断头/节表、
节越界、坏 shstrndx；PE 节越界、MZ 截断；Mach-O fat 拒绝等。
所有相关用例都用 `t.Logf` 打印**输入摘要与判定依据**（`go test -v` 可见）。

关键测试：

- `internal/binary`：三种格式 happy path + `TestParseTruncatedAndMalformed` 错误分类。
- `internal/rules`：`TestRuleVersionReproducibility`（版本切换、哈希、历史结论不漂移）、
  `TestLoadSetRejectsInvalidRules`、定位/权限/入口点规则。
- `internal/scan`：`TestConcurrentScanMatchesSequentialAndOrderStable`、
  `TestCacheReuseAndSingleflight`、`TestLimitsSynchronousRejection`、
  `TestTimeoutTerminatesWithDefiniteStatus`（注入慢 Evaluator，确定性验证超时）、
  `TestRuleSetVersionPinnedInResult`、`TestMalformedSamplesDistinguished`。
- `cmd/binsa`：端到端 JSON 报告与退出码。

## 已知限制

- 缓存为进程内内存实现，不跨进程持久化（接口 `scan.Cache` 可自行扩展）。
- 规则当前只覆盖结构元数据、节权限/名称、字节/正则匹配；不做反汇编、签名解压或
  导入/导出表深度解析。
- 仅支持 thin Mach-O；fat 容器按“不支持的变体”明确拒绝。
