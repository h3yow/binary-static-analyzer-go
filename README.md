# binary-static-analyzer-go

本地二进制静态分析与检出工具链：把不同格式的可执行文件解析成统一结构模型，
用**带版本的规则集**做可复现匹配，并支持多目标并发扫描与结果缓存。

## 目录结构

| 包 | 职责 |
| --- | --- |
| `internal/model` | 与格式无关的统一结构模型（节区、导入、入口点、熵、SHA-256 等） |
| `internal/parser` | ELF / PE / Mach-O 解析与**可区分的失败分类** |
| `internal/rules` | 规则模型、严格校验加载、匹配引擎、确定性排序 |
| `internal/scan` | 并发调度、内容去重、结果缓存、资源/超时语义 |
| `cmd/analyzer` | 本地 CLI，输出确定性 JSON 报告 |

## 支持的格式

| 格式 | 支持内容 | 不支持 / 明确拒绝 |
| --- | --- | --- |
| **ELF** | ELF32/ELF64、大小端、x86/x86_64/ARM/ARM64、节区表、`.shstrtab`、`shnum==0`/`shstrndx==SHN_XINDEX` 扩展形式、节区熵 | 非法 `EI_CLASS/EI_DATA`、越界节区等报 `corrupt`/`truncated` |
| **PE** | PE32/PE32+、小端、COFF 节区表、长名（`/123` 指向 COFF 字符串表）、入口点 | 仅识别 `MZ`+`PE\0\0`；其它可选头 magic 报 `corrupt` |
| **Mach-O** | 32/64 位 thin、大小端、`LC_SEGMENT[_64]` 内节区、`LC_MAIN` 入口 | **fat/universal 明确报 `unsupported`**，不静默处理 |

解析永远不会因为截断或损坏而 panic 或静默跳过：所有整数读取与切片都做了
边界检查。失败通过哨兵错误 + `ParseError{Cause, Format, Detail, Offset}` 表达，
用 `errors.Is` 区分：

| 哨兵错误 | 含义 |
| --- | --- |
| `parser.ErrEmpty` | 输入为空 |
| `parser.ErrUnknownFormat` | 没有任何受支持的 magic |
| `parser.ErrTruncated` | 声明的结构越过文件末尾（文件被截断） |
| `parser.ErrCorrupt` | 结构在位但关键字段非法（class、endian、magic、索引越界等） |
| `parser.ErrUnsupported` | 识别了格式但该变体不支持（如 fat Mach-O） |
| `parser.ErrOversized` | 声明大小超过配置上限 |

## 规则模型

规则集是一个 JSON 文档，带必填的 `version`，规则数组**冻结为不可变集合**：

```json
{
  "version": "2026.09.0",
  "rules": [
    {"id": "SEC-UPX", "scope": "section_name", "match": "contains",
     "pattern": "upx", "severity": "medium", "description": "UPX 节区"}
  ]
}
```

- `scope`：`format` / `arch` / `section_name` / `section_bytes` / `import`
- `match`：`exact` / `contains` / `prefix` / `suffix` / `regexp` / `hex`
  （`hex` 仅允许用于 `section_bytes`，pattern 是可含空白的十六进制串）
- 加载是**严格**的：未知字段、空版本、空规则集、重复 id、未知枚举、
  非法正则/非法 hex 都会返回包裹 `rules.ErrInvalidRuleSet` 的错误。
- 每条命中都带**判定依据**：`Location{Section, Offset(绝对文件偏移), Length, Detail}`
  以及实际匹配值 `Matched`（字节命中为 hex 文本）。
- 命中按 `(rule id, section, offset, matched)` 稳定排序，结论确定性。

### 版本与可复现性

- 一个 `Engine` 永久绑定一个规则集版本；升级规则 = 新建一个 Engine。
- 扫描缓存的键是 `(输入内容 SHA-256, 规则版本)`。因此：
  - 同一份样本在同一规则版本下，任意次扫描结论一致（含跨进程内多次 Scan）；
  - 规则升级后**绝不会**复用旧版本的结论，也不会让历史结论悄悄改变；
  - 降级回旧版本，仍能得到当初的历史结论（见
    `TestIntegration_VersionSwitchReproducible`）。
- 报告里每个结果都带 `rule_version`，判定可追溯到具体规则版本。

## 并发与缓存语义

- `MaxConcurrency` 限制同时进行的解析/匹配任务数（默认 4）。
- 同一次 Scan 中**内容相同的目标只解析/评估一次**，多个位置共享同一结论
  （`TestScan_DuplicateContentScannedOnce` 用计数解析器验证只调用一次）。
- 结果始终按**输入顺序**返回，与完成顺序无关；并发扫描结论与逐个扫描逐字段
  一致（`TestScan_OrderStableAndMatchesSequential`）。
- 跨 Scan 调用，相同内容 + 相同规则版本直接命中缓存；缓存做防御性拷贝，
  调用方无法污染缓存。
- 资源上限 `MaxTargetSize`：超限目标不进入调度，直接 `status=rejected`、
  `error.kind=too_large`；文件读取用 `LimitReader(limit+1)`，不会把超大文件
  读进内存。
- `PerTargetTimeout`：单个目标超时 → 该目标 `status=timeout`，其它目标继续。
- `OverallTimeout`：整批截止后未完成目标全部 `status=timeout`，已完成目标保留
  结论，调用返回包装 `scan.ErrTimeout` 的错误，**不会挂住也不会吞错**。
- 解析与匹配都响应 `context.Context`；所有代码通过 `go test -race`。

## CLI

```bash
go build ./cmd/analyzer

./analyzer \
  -rules rules.example.json \
  -jobs 8 \
  -max-size $((256*1024*1024)) \
  -per-target-timeout 5s \
  -overall-timeout 60s \
  /bin/ls /path/to/a.exe /path/to/truncated
```

输出为确定性 JSON（snake_case）。每个结果含 `status`、`hash`、`rule_version`、
`findings`；失败时 `error.kind` 是机器可区分的类别（`truncated` / `corrupt` /
`unknown_format` / `unsupported` / `oversized` / `too_large` / `timeout`）。

退出码：`2` 参数/规则错误，`3` 运行被整体超时/取消终止，`10` 至少一条命中，
`0` 无命中且正常完成。

## 验证方法

```bash
# 全部单测（包含畸形/截断样本与规则版本切换）
go test ./...

# 竞态检测 + 重复运行验证并发稳定性
go test -race ./...
go test -count=5 ./internal/...

# 详细日志：打印每个输入（长度/头部字节）与判定依据（偏移、原因、命中）
go test -v ./internal/parser/ ./internal/rules/ ./internal/scan/
```

测试覆盖要点：

- **畸形/截断**：ELF（短 e_ident、非法 class/endian、越界 shoff、非法
  shstrndx、越界节区数据）、PE（截断 MZ、`e_lfanew==0`、节区数据截断、
  非法可选头 magic）、Mach-O（截断头、fat 拒绝、非法 cmdsize）。
- **错误可区分**：每类用例都断言具体的 `errors.Is` 哨兵错误，而非只看失败。
- **规则版本切换**：`rules.TestRuleVersionIsolation` 与
  `scan.TestIntegration_VersionSwitchReproducible` 双向验证。
- **并发/缓存**：顺序稳定、并发==逐个、重复内容只解析一次、跨调用缓存复用、
  版本变更缓存失效、超限拒绝、单目标/整体超时不挂住。
