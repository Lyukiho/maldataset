# PE Malware Detection — Feature Set

## 数值特征（10个）

| # | 特征名 | 类型 | 含义 | 计算方法 |
|---|---|---|---|---|
| 1 | `section_entropy_max` | 浮点 | 最大节熵值 | 遍历所有节计算 Shannon 熵，取最大值 |
| 2 | `section_max_raw_size` | 浮点 | 最大节原始大小（开根号） | 取所有节 SizeOfRawData 最大值，再取平方根压缩长尾分布 |
| 3 | `nonstandard_section_name_count` | 整数 | 非标准节名数量 | 节名不在 COMMON_SECTION_NAMES 集合中的数量（见下方24个常见名） |
| 4 | `standard_section_name_count` | 整数 | 标准节名数量 | 节名在 COMMON_SECTION_NAMES 集合中的数量 |
| 5 | `user32_minus_crt_import_count` | 整数 | GUI行为 vs 通用库 | user32.dll 导入项总数 减去 CRT 导入项总数 |
| 6 | `debug_directory_present` | 0/1 | Debug目录是否存在 | DATA_DIRECTORY[6] 的 VirtualAddress 和 Size 均非零 |
| 7 | `entry_section_rwx` | 0/1 | 入口节是否 RWX | 入口点所在节是否同时 readable + writable + executable |
| 8 | `embedded_payload_ratio` | 浮点 | 嵌入载荷比率 | max(resource目录大小, 非证书overlay大小) / 文件总大小 |
| 9 | `timestamp_implausible` | 0/1 | 编译时间戳是否异常 | 结合 PE Linker 版本判断时间戳是否合理（见下方检测规则） |
| 10 | `checksum_zero` | 0/1 | CheckSum 是否为 0 | PE Optional Header 的 CheckSum 字段是否为 0 |

## 分类特征（1个）

| # | 特征名 | 取值 | 含义 | 计算方法 |
|---|---|---|---|---|
| 11 | `directory_presence_pattern` | 0-63 整数 | 数据目录存在位掩码 | 6-bit 掩码，bit0=export, bit1=debug, bit2=load_config, bit3=resource, bit4=basereloc, bit5=tls |

---

## `timestamp_implausible` 检测规则

> 核心思想：编译时间不能晚于“当下”，也不能早于“编译该 PE 的 Linker 被发布出来的时间”。

### 检测流程

1. 从 `FILE_HEADER.TimeDateStamp` 读取 Unix timestamp
2. 如果 timestamp 为 0，返回 `0`（没填 ≠ 填错了，这是另一维度的信息）
3. 将 timestamp 转为 UTC 年份
4. **未来检测**：年份 > 当前年份 → `1`（implausible）
5. **Linker-aware 早于检测**：查下表，年份 < 该 Linker 版本的最早发布年份 → `1`
6. 其他情况 → `0`

### Linker 主版本 → 最早发布时间

| Linker Major | 对应工具链 | 最早年份 |
|---|---|---|
| 6 | Visual C++ 6.0 | 1998 |
| 7 | VS .NET 2002 | 2002 |
| 8 | VS 2005 | 2005 |
| 9 | VS 2008 | 2008 |
| 10 | VS 2010 | 2010 |
| 11 | VS 2012 | 2012 |
| 12 | VS 2013 | 2013 |
| 14 | VS 2015 / 2017 / 2019 / 2022 | 2015 |
| 15 | VS 2017+ | 2017 |
| 其他 | 未知 Linker | 不做早于检测（仅检测未来） |

### 示例

| Timestamp | Linker Major | 判定 | 原因 |
|---|---|---|---|
| `0` | 任意 | `0` ok | 没填时间戳，不算异常 |
| `2022-01-01` | 14 | `0` ok | VS2015 发布于 2015，2022 在其之后 |
| `1999-01-01` | 14 | `1` implausible | VS2015 尚未发布，不可能用它编译出 1999 年的 PE |
| `1999-01-01` | 6 | `0` ok | VC6 发布于 1998，1999 在其之后 |
| `2099-01-01` | 14 | `1` implausible | 远在未来 |
| `2022-01-01` | 99 | `0` ok | 未知 Linker，不应用早于规则 |

### 真实数据抽样表现

| | benign (n=10) | malware (n=10) |
|---|---|---|
| `timestamp_implausible=1` | 6 | 0 |
| `checksum_zero=1` | 0 | 6 |

- **良性** 时间戳异常更多：老文件、第三方不规范编译导致时间戳被改写
- **恶意** `checksum=0` 占主流：恶意作者不计算校验和，正常签名 PE 则几乎都有

---

## `checksum_zero` 检测规则

直接从 `OPTIONAL_HEADER.CheckSum` 读取。为 0 → `1`，否则 → `0`。

正常编译流程通常为 PE 计算校验和（驱动必须，普通 exe/dll 可选但绝大多数编译器会填）。恶意样本经常是手工构造或被工具 strip 后丢失。

---

## 辅助常量和定义

### COMMON_SECTION_NAMES（24个标准节名）
```
.text, .code, code, .data, data, .rdata, .bss, bss,
.idata, .edata, .pdata, .xdata, .sxdata, .rsrc, .reloc,
.tls, .crt, .debug, .didat, .gfids, .giats, .gljmp, .00cfg
```

### DIRECTORY_PATTERN_BITS（位掩码映射）
```
bit 0 → export       (DATA_DIRECTORY[0])
bit 1 → debug        (DATA_DIRECTORY[6])
bit 2 → load_config  (DATA_DIRECTORY[10])
bit 3 → resource     (DATA_DIRECTORY[2])
bit 4 → basereloc    (DATA_DIRECTORY[5])
bit 5 → tls          (DATA_DIRECTORY[9])
```

### 动态加载API集合（DYNAMIC_LOAD_APIS）
```
LoadLibraryA, LoadLibraryW, LoadLibraryExA, LoadLibraryExW,
GetProcAddress, LdrLoadDll
```

### 文件打开API集合（FILE_OPEN_APIS）
```
CreateFileA, CreateFileW, CreateFile2, NtCreateFile, ZwCreateFile
```

### 文件写入API集合（FILE_WRITE_APIS）
```
WriteFile, WriteFileEx, NtWriteFile, ZwWriteFile
```

### CRT DLL 匹配规则（is_crt_dll）
```
msvcrt.dll, ucrtbase.dll, api-ms-win-crt-*,
vcruntime*.dll, msvcp*.dll
```

---

## 变更记录

| 日期 | 变更 | 原因 |
|---|---|---|
| 2026-07-27 | 删除 `imports_kernel32_virtualalloc`、`imports_kernel32_loadlibrarya`、`linker_version_unknown`、`payload_handling_pattern` | 随机切分后 importance 全部归零，去掉后模型无退化 |
| 2026-07-27 | 训练/测试切分改为随机 60/40 | 原顺序切分有系统性偏差，随机后 entropy 重要性从 0.010→0.060，模型从 95%→98% |
| 2026-07-27 | `section_max_raw_size` 取平方根 | 原始值长尾分布严重，importance 恒为 0；开根号后 importance 0.012 |
| 2026-07-27 | 混淆矩阵改为百分比显示 | 每格显示行百分比 + 样本数 |
| 2026-07-27 | 删除 `arch_structure_anomaly_score` | 在该数据集上 permutation importance 恒为 0 |
| 2026-07-27 | `section_entropy_max_gt_6.5`(二值) → `section_entropy_max`(连续) | 二值化丢掉细粒度信息，重要性从 0.012→0.111 |
| 2026-07-27 | `section_max_raw_size_gt_100000`(二值) → `section_max_raw_size`(连续) | 阈值 100KB 太高几乎不触发，重要性从 0→0.008 |
| 2026-07-27 | 删除 `has_empty_section_name` | permutation importance 为 0 |
