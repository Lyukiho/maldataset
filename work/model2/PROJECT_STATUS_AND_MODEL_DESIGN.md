# PE 恶意样本自然语义检测项目：现状、实验记录与模型设计

> 更新时间：2026-08-12  
> 工作目录：`E:\StudyFiles\project\yukiho\maldataset\model2`  
> 本文档汇总目前的全部有效信息、已经完成的处理、失败尝试、实验结果、设计判断和下一步计划。  
> 所有样本分析均为静态分析，没有运行任何待分析 PE。

## 1. 项目目标

目标是实现一个参数量较小、主要依靠 IDA/Hex-Rays 等静态反编译结果的模型，用自然语义判断 Windows PE 样本是否恶意，并尽量给出可核查的函数级证据。

这里的“自然语义”不是简单统计字节、节熵或导入数量，而是让模型理解类似下面的程序逻辑：

- 创建或修改注册表实现持久化；
- 创建进程、服务或计划任务；
- 建立网络连接、收发数据；
- 动态加载 API、修改内存权限；
- 枚举系统、检测调试器；
- 解密配置、释放或注入 payload。

项目当前约束：

- 优先使用 IDA、IDAPython 和 Hex-Rays；
- 尽可能保持纯静态分析；
- `model1` 不在本项目范围内；
- 第一版不追求通用自动解壳；
- 模型应能拒绝对证据不足的样本作出过度自信的判断。

## 2. 当前数据资产

### 2.1 工作区内原有有标签数据

根目录的 `dataset.csv` 当前有 2,179 条记录：

| 标签 | 数量 |
|---|---:|
| 良性（0） | 747 |
| 恶意（1） | 1,432 |

主要来源如下：

| 来源 | 数量 | 说明 |
|---|---:|---|
| `virusshare` | 603 | 恶意样本为主 |
| `existing_benign` | 511 | 原有良性文件 |
| `dike_batch7` | 101 | 同时存在少量恶意和大量良性 |
| `malware_database` | 100 | 恶意样本 |
| `dike_batch8` | 100 | 恶意样本 |
| `dike_batch3` | 99 | 良性样本 |
| `dike_batch9` | 98 | 恶意样本 |
| `dike_batch5` | 98 | 恶意样本 |
| `dike_batch2` | 98 | 恶意样本 |
| `dike_batch4` | 98 | 恶意样本 |
| `dike_batch6` | 93 | 恶意样本 |
| `dike_batch10` | 85 | 恶意样本 |
| `dike_batch1` | 55 | 恶意样本 |
| `generated_win32_api` | 40 | 生成式良性程序，只适合作补充 |

目录内实际文件数与 `dataset.csv` 条目数略有差异，因此后续训练应以经过校验的 manifest 为准，不能仅按文件夹计数。

### 2.2 BODMAS 五个 batch

远程数据位于服务器的 `/bodmas_malware_dataset_batches`，已选择前 5 个 batch。远程连接口令不写入本文档。

拷贝过程经历过一次杀毒软件拦截；用户关闭杀毒软件后重新开始。为避免系统盘空间压力，数据放在 D 盘。当前相关目录：

- 消毒后的原始副本：`D:\bodmas_malware_dataset_batches`
- IDA 可分析修复副本：`D:\bodmas_malware_dataset_batches_ida`
- IDA 试点输出：`D:\bodmas_ida_analysis\pilot`

五个 batch 共 5,000 个样本、约 13.585 GiB。BODMAS 这批数据全部属于恶意侧，具有家族标签，但不能单独用于训练恶意/良性二分类器。

## 3. BODMAS PE 头修复

### 3.1 问题

这批样本经过“消毒”：

- COFF `Machine` 被清零；
- Optional Header 的 `Subsystem` 通常也被清零。

`Machine=0` 会让 IDA/Ghidra 一类工具无法可靠选择 x86 或 x64 处理器。`Subsystem=0` 表示未知子系统，可能影响 Windows 正常加载执行，但静态反编译工具通常并不依赖它判断指令架构。

### 3.2 修复原则

实现了非破坏性的修复脚本 [`repair_bodmas_pe_headers.py`](repair_bodmas_pe_headers.py)：

- 从 Optional Header Magic 推断架构：
  - PE32 `0x10B` → `Machine=0x014C`（x86）；
  - PE32+ `0x20B` → `Machine=0x8664`（x64）。
- 默认保留 `Subsystem=0`，因为原始值无法可靠恢复；
- 只生成新副本，不覆盖消毒后的输入；
- 先写 `.part`，完成校验后原子替换；
- 校验文件大小、MZ/PE 签名、Optional Header 和架构一致性；
- 分别记录数据集 SHA、输入文件真实 SHA 和修复后真实 SHA；
- 重复执行时验证并跳过已正确修复文件。

脚本允许显式设置合成的 GUI Subsystem，但该值会在 manifest 中标记为 synthetic，不能作为训练特征。当前实际修复没有使用这一选项。

### 3.3 修复结果

`D:\bodmas_malware_dataset_batches_ida\repair_manifest.csv` 中有 5,000 条唯一记录：

| 指标 | 结果 |
|---|---:|
| 总样本 | 5,000 |
| PE32/x86 | 4,886 |
| PE32+/x64 | 114 |
| `Subsystem=0` | 5,000 |
| 合成 Subsystem | 0 |
| 新修复 | 4,999 |
| 已存在且复核正确 | 1 |
| 失败 | 0 |

### 3.4 关于 `Subsystem=0` 的最终判断

- 它不妨碍当前 IDA 9 识别 x86/x64；
- 它没有阻碍 IDA 建立函数；
- 它没有阻碍 Hex-Rays 生成伪代码；
- 它可能阻止或改变 Windows 对文件的正常执行加载，但本项目本来就不执行样本；
- 强行猜成 GUI 或 Console 会制造伪特征，因此默认保留 0 是更稳妥的选择。

当前反编译质量的主要障碍是加壳、压缩、异常控制流和导入表破坏，不是 `Subsystem=0`。

详细修复说明见 [`BODMAS_REPAIR.md`](BODMAS_REPAIR.md)。

## 4. 全量静态筛查

### 4.1 已实现的筛查器

[`static_triage.py`](static_triage.py) 对修复后的 5,000 个样本进行只读静态筛查。它目前使用 `pefile` 做快速预筛，正式模型所需的主要结构仍计划由 IDA 导出。

当前提取内容包括：

- PE 类型、节数和节名；
- 导入模块、导入 API 数量；
- 可执行节最大熵；
- 入口点所在节及入口节熵；
- W+X 节数量；
- TLS、.NET、Authenticode 目录；
- overlay 大小；
- 常见壳节名；
- 低导入 + 高熵；
- 入口位于空节或高熵 W+X 节等异常。

当前 `likely_packed` 是启发式标签，不是可靠的壳真值。主要规则为：

- 节名包含常见壳/压缩器词；或
- 导入数不超过 8 且可执行节熵至少为 7.1；或
- 入口节 Raw Size 为 0；或
- 入口节同时可写、可执行且熵较高。

### 4.2 全量结果

5,000/5,000 样本最终均成功筛查：

| 指标 | 数量 | 比例 |
|---|---:|---:|
| 疑似加壳/压缩 | 2,234 | 44.7% |
| 至少一个 W+X 节 | 2,457 | 49.1% |
| TLS 目录 | 1,193 | 23.9% |
| .NET | 114 | 2.3% |
| Authenticode 目录 | 32 | 0.6% |

主要家族的疑似加壳比例：

| 家族 | 样本数 | 疑似加壳 | 比例 |
|---|---:|---:|---:|
| Sfone | 407 | 288 | 70.8% |
| Wacatac | 384 | 345 | 89.8% |
| Upatre | 331 | 110 | 33.2% |
| Wabot | 320 | 38 | 11.9% |
| Small | 274 | 6 | 2.2% |
| Dinwod | 216 | 213 | 98.6% |
| Ganelp | 204 | 156 | 76.5% |
| Mira | 167 | 20 | 12.0% |
| Berbew | 161 | 0 | 0.0% |
| Sillyp2p | 133 | 45 | 33.8% |
| Benjamin | 123 | 123 | 100.0% |
| Ceeinject | 117 | 104 | 88.9% |
| Autoit | 96 | 56 | 58.3% |
| Gepys | 88 | 12 | 13.6% |
| Musecador | 88 | 0 | 0.0% |

结论是“壳状态”和“家族”高度相关。如果随机按文件划分 train/test，模型很容易通过某个家族常用的壳、编译模板或节布局猜标签，而不是学习恶意行为语义。

### 4.3 筛查器修复记录

首次运行时有 3 个 Upatre 样本报 `IndexError`。原因不是样本损坏，而是它们合法地声明了少于 15 项的数据目录表，脚本却直接访问第 15 项。.NET、签名和 TLS 目录检查现已增加长度边界；缺失项按“不存在”处理。重新运行后 5,000/5,000 成功。

全量结果见 [`bodmas_static_triage_5000.csv`](bodmas_static_triage_5000.csv)。

## 5. IDA 静态提取流水线

### 5.1 IDA 环境

当前 IDA 路径：

```text
E:\Appself\IDA Pro-v9.0 RC1-Windows\IDA Pro-v9.0 RC1-Windows\idat.exe
```

已确认安装中包含 Hex-Rays 和 IDAPython，试点中能够对 x86/x64 样本生成伪代码。

### 5.2 单样本 IDAPython 提取器

[`ida_extract_sample.py`](ida_extract_sample.py) 在 IDA 内运行，流程为：

1. 等待 IDA 自动分析结束；
2. 枚举导入模块和 API；
3. 枚举字符串及其所属函数引用；
4. 枚举全部恢复出的函数；
5. 对每个函数导出：
   - 地址和大小；
   - 指令数量；
   - 基本块、CFG 边；
   - callee/caller；
   - API 引用；
   - 字符串引用；
   - 高频 mnemonic；
   - 库函数/thunk 标志；
   - 敏感行为类别。
6. 对函数进行排序；
7. 最多选择 48 个函数调用 Hex-Rays；
8. 将结构和伪代码写入 JSON。

函数选择综合考虑：

- 距离入口点的调用距离；
- 是否引用敏感 API；
- 导入和字符串数量；
- 函数大小；
- caller 数量；
- 少量确定性的随机补样，避免只选择同一类函数。

每函数伪代码上限为 100,000 字符，字符串导出数量和长度也有限制，防止异常样本制造无限大的输出。

敏感类别目前包括：进程注入、内存权限、持久化、网络、动态 API 解析、反分析、凭据/密码学。它们用于函数排序和解释，不直接等同于恶意标签。

### 5.3 批处理器

[`run_ida_batch.py`](run_ida_batch.py) 提供：

- CSV 选择清单；
- 多 worker；
- 单样本超时；
- 已有 JSON 自动续跑；
- IDA 日志；
- 可选保留或删除 IDB/I64 数据库；
- 每次运行生成 manifest。

默认试点设置为：每样本最多反编译 48 个函数、每样本超时 180 秒、两个并发 worker。

### 5.4 IDA 9 兼容问题与修复

早期提取器遇到过几处 IDA 9 API 差异，已修正：

- 字符串数量改为通过迭代统计；
- 函数标志使用 `function.flags`；
- IDA 版本改用 `ida_kernwin.get_kernel_version()`；
- x64 Hex-Rays 调用经过实际样本验证。

曾直接运行 `idat.exe -v`，该进程出现挂起并被终止。该现象与后续成功的带样本批分析并不矛盾，但说明不能用 `-v` 是否立即返回作为环境健康检查。

## 6. BODMAS IDA 试点

### 6.1 试点设计

试点最终包含 15 个有效 JSON：

- 静态筛选出的 13 个代表样本；
- 额外分析的 Wacatac x86 和 Wacatac x64；
- 覆盖 x86/x64；
- 覆盖疑似加壳和未加壳；
- 覆盖多个主要家族。

原始选择清单见 [`ida_pilot_selection.csv`](ida_pilot_selection.csv)，汇总见 [`ida_pilot_results.csv`](ida_pilot_results.csv)。

### 6.2 逐样本结果

| 家族 | 架构 | 静态疑似壳 | 函数数 | 已反编译 | 导入 | 字符串 | 质量判断 |
|---|---|---:|---:|---:|---:|---:|---|
| Berbew | x86 | 否 | 1 | 1 | 142 | 297 | semantic 候选 |
| Drolnux | x86 | 否 | 67 | 30 | 39 | 673 | semantic 候选 |
| GandCrab | x86 | 否 | 966 | 48 | 95 | 794 | semantic 候选 |
| Mira | x86 | 否 | 1,109 | 48 | 76 | 439 | semantic 候选 |
| Musecador | x86 | 否 | 130 | 17 | 114 | 243 | semantic 候选 |
| Small | x86 | 否 | 125 | 15 | 54 | 237 | semantic 候选 |
| Vools | x64 | 否 | 423 | 48 | 97 | 715 | semantic 候选 |
| Wabot | x86 | 否 | 359 | 48 | 89 | 392 | semantic 候选 |
| Benjamin | x86 | 是 | 1 | 1 | 15 | 648 | 壳/混淆 |
| Ceeinject | x86 | 是 | 6 | 6 | 91 | 2,005 | 壳/混淆 |
| Dinwod | x86 | 是 | 5 | 5 | 2 | 321 | 壳/解压 stub |
| Upatre | x86 | 否 | 2 | 2 | 25 | 30 | 拓扑异常，按壳/混淆处理 |
| Wacatac | x86 | 是 | 5 | 5 | 2 | 321 | 壳/解压 stub |
| Wacatac | x64 | 是 | 1 | 1 | 11 | 1,866 | 壳/解压 stub |
| Sfone | x86 | 是 | 0 | 0 | 9 | 238 | 不可用 |

汇总：

| 质量组 | 数量 |
|---|---:|
| `pseudocode_candidate` | 8 |
| `unpacking_or_obfuscated` | 6 |
| `unusable` | 1 |

8 个 semantic 候选共恢复 3,180 个函数，其中按上限和排序选出 255 个函数，255/255 均成功生成伪代码。

### 6.3 样本级观察

#### Wacatac x86 与 Dinwod

两者都表现为：

- 5 个函数；
- 747 条总指令；
- 最大函数 453 条指令；
- 2 个导入；
- 321 个字符串；
- IDA 日志提示导入区损坏/疑似 packed；
- 伪代码主要是解压循环、动态解析和内存权限修改。

这说明模型很容易学到共享包装层，而不是家族 payload。它们也可能存在相同或高度相似的包装模板，后续必须进行近重复/壳簇审计。

#### Wacatac x64

- 只有 1 个函数；
- 885 条指令、150 个基本块；
- 有 `LoadLibraryA`、`GetProcAddress`、`VirtualProtect` 等导入；
- 伪代码表现为 XOR 解码、类似 LZMA 的解压循环、动态 API 解析，最后跳向解压入口；
- 出现 positive-SP 和异常跳转。

虽然 Hex-Rays 能输出伪代码，但它描述的是 unpacker，不是最终恶意逻辑。

#### Sfone

IDA 能看到 9 个导入和 238 个字符串，但函数数为 0，且日志提示导入区异常。该样本不能进入伪代码语义分类器。

#### Upatre

静态启发式没有标为 packed，但 IDA 只恢复 2 个函数，其中最大函数 300 条指令。这说明质量 gate 必须结合 IDA 恢复拓扑，不能只看节熵和导入数。

#### 可语义分析样本

- Wabot 命中网络相关 API；
- Vools 同时出现反分析、动态解析、内存权限和持久化；
- GandCrab 出现动态解析、内存权限和持久化；
- Mira、Small 出现持久化相关线索。

这些只能作为“可疑行为证据”，不能单凭一个 API 判断恶意，因为良性安装器、更新器和管理工具也可能调用相同接口。

## 7. 本地有标签对照试验及失败记录

为了验证恶意/良性差异，而不是只分析 BODMAS 恶意家族，生成了 [`local_ida_pilot_selection.csv`](local_ida_pilot_selection.csv)，包含：

- 6 个良性样本；
- 6 个恶意样本；
- 良性来源覆盖 `existing_benign`、`generated_win32_api` 和 Dike；
- 恶意来源覆盖 VirusShare、Malware Database 和 Dike。

实际尝试结果：

1. 两个 worker 启动批处理；
2. 前 6 个良性样本均在 180 秒后超时；
3. 所有样本都没有生成 IDA 日志，说明挂起发生在正式自动分析前；
4. 外层批处理在 600 秒后停止，未继续把剩余恶意样本跑完；
5. 将一个良性 DLL 复制到 D 盘后单独重试，仍在 120 秒后无日志超时；
6. 用 `pefile` 检查 12 个样本，均有合法的 Machine、Subsystem、节表和 16 项数据目录；
7. 超时不能被解释为“样本无法反编译”，更可能是当时的 IDA 启动、许可、文件访问或系统拦截状态；
8. 遗留的 `idat.exe` 进程已终止/清理，没有继续运行。

由于 BODMAS 试点此前能正常使用同一个 IDA 和同一提取脚本，这一故障需要独立复现。修复前不能把本地对照组超时计入模型数据质量统计。

## 8. 当前最重要的经验判断

### 8.1 不能把整文件伪代码当成一个普通长文本

试点中每文件函数数从 0 到 1,109 不等。直接拼接会造成：

- 输入长度不可控；
- 大程序淹没关键恶意函数；
- 小壳 stub 被模型过度关注；
- 模型学到函数数量、编译器运行时和填充模式；
- 很难输出稳定的函数级证据。

因此模型必须是“函数级编码 + 文件级聚合”。

### 8.2 不能把文件标签赋给每个函数

恶意 PE 中包含大量普通函数、运行库、解压库和编译器模板。如果把恶意文件内所有函数都标为恶意，会制造严重标签噪声。更合适的是多实例学习：文件是一个 bag，函数是 instance，只有文件有标签。

### 8.3 有壳样本的伪代码不等于 payload 语义

若 IDA 只看到解压器，即使模型判断正确，也可能只是识别了壳。这样的模型可以作为静态风险模型，但不能声称理解了最终程序行为。

### 8.4 数据泄漏风险高于模型结构选择

BODMAS 的壳比例与家族强相关，本地数据的标签也与来源强相关。如果按文件随机切分，即使获得很高准确率，也很可能没有泛化价值。

## 9. 推荐总体模型：可拒判的分层语义模型

推荐架构：

```text
PE 文件
  │
  ├─ IDA/PE 质量 Gate
  │     ├─ semantic ──────→ 函数伪代码编码器 ─→ MIL/调用图聚合 ─┐
  │     ├─ packed_stub ───→ 壳/低层特征专家 ───────────────────┤
  │     └─ unusable ──────→ 拒判/证据不足 ─────────────────────┤
  │                                                            │
  └─ IDA 全局结构特征 ──────────────────────────────────────────┤
                                                               ↓
                                      恶意概率 + 分析可靠度 + 证据函数
```

第一版建议只训练 `semantic` 分支；`packed_stub` 返回低置信度或拒判。这样最容易验证模型是否真的利用了反编译语义。

## 10. 质量 Gate 设计

### 10.1 输入

尽量使用 IDA 可导出的信号：

- 函数数量；
- 选择函数数和 Hex-Rays 成功率；
- 最大函数指令数、基本块数；
- 是否只有 1--5 个大函数；
- positive-SP、`JUMPOUT` 和反编译错误；
- 入口点到函数的可达性；
- 导入区异常；
- 导入和字符串数量；
- `LoadLibrary/GetProcAddress/VirtualProtect` 等是否集中于入口 stub；
- 可执行节熵、W+X、节名、入口节异常；
- 调用图规模和连通性。

### 10.2 输出

- `semantic`：看到了足够的实际逻辑；
- `packed_stub`：主要是壳、解压、自修改准备或极小入口；
- `unusable`：无法建立足够函数/伪代码；
- 连续的 `analysis_reliability`，用于最终概率校准。

第一版可以使用规则和轻量树模型。等有人工复核的质量标签后，再训练 gate。不能仅依据静态 `likely_packed`，因为 Upatre 已证明存在漏判。

## 11. 函数输入表示

每个函数单独构造结构化文本，例如：

```text
<FUNCTION>
<ENTRY_DISTANCE> 2
<CALLERS> 4
<CALLEES> 7
<CFG> blocks=12 edges=18
<APIS> RegCreateKeyExW RegSetValueExW CreateProcessW
<STRING_TYPES> registry_path executable_path command_line
<PSEUDOCODE>
if ( RegCreateKeyExW(...) == 0 ) {
    RegSetValueExW(...);
}
```

规范化建议：

- `sub_401000`、`loc_...`、`v12` 等替换为稳定占位符；
- 地址替换为 `<ADDR>`；
- 一般大常量归一化；
- 保留端口、权限标志、协议号等有语义常量；
- 完整保留 Windows API 名称；
- 字符串同时保留截断内容和类别，如 URL、IP、路径、注册表、命令行、互斥体；
- 删除 IDA 注释噪声和无意义类型转换；
- 库函数、thunk、编译器运行时函数不进入主要候选；
- 对明显解压循环添加 `<UNPACKING_STUB>`，但不能把它当 payload 行为。

## 12. 函数选择

建议每文件选择 24--48 个函数。候选来源包括：

- 入口可达函数；
- 引用敏感 API 的函数；
- 引用高价值字符串的函数；
- caller 较多的枢纽函数；
- CFG 较复杂但不过度异常的函数；
- 少量随机函数，防止完全由启发式决定输入。

还应控制：

- 不让一个 2,000 指令函数占满全部 token；
- 长函数按基本块或语义区域切片；
- 每个函数单独编码，避免函数边界丢失；
- 记录未被选择函数的全局统计，作为额外特征。

## 13. 语义编码器与 PE 聚合

### 13.1 编码器

第一版适合使用约 125M 参数的代码/自然语言预训练编码器，例如 CodeBERT 或 UniXcoder 这一档，而不是从头训练语言模型或直接上大规模生成式模型。

理由：

- 当前有标签样本仅数千级；
- 编码器分类比生成式问答更稳定、更便宜；
- 便于缓存函数 embedding；
- 可以冻结底层或使用 LoRA/部分层微调；
- 更适合多实例聚合。

### 13.2 MIL 聚合

设第 `i` 个函数表示为：

```text
h_i = Encoder(function_i)
```

通过 attention 计算函数权重：

```text
a_i = softmax(wᵀ tanh(V h_i + graph_bias_i))
z_semantic = Σ a_i h_i
```

再与 IDA 全局特征 `g` 融合：

```text
p_malware = sigmoid(MLP([z_semantic, g, analysis_reliability]))
```

第一版可先不使用复杂 GNN，只做 attention MIL。后续加入调用图边作为 attention bias，或增加浅层 GraphSAGE/GAT。样本量不大时，复杂图网络可能更容易过拟合家族模板。

### 13.3 多任务输出

至少两个输出头：

1. `malicious_probability`：恶意概率；
2. `analysis_reliability` / `route`：分析质量和路由。

可以增加辅助行为头：持久化、网络、注入、反分析、凭据访问等。辅助行为不必有完美真值，初期可由规则提供弱标签，但不能代替恶意标签。

预期输出：

```text
malicious_probability: 0.93
analysis_reliability: 0.87
route: semantic
evidence:
  - function_17: registry persistence
  - function_31: process creation
  - function_08: network communication
```

自然语言摘要更适合作为对 top evidence functions 的后处理解释，而不是第一版分类链路的必要输入。先摘要再分类会引入幻觉和信息损失。

## 14. 有壳样本的三种处理方案

### 方案 A：拒判或低置信度，推荐作为 MVP

当 gate 判断只看到 unpacker 时输出：

```text
route: packed_stub
malicious_probability: unavailable
analysis_reliability: 0.18
reason: only unpacking stub recovered
```

优点是语义结论诚实、评测边界清楚。缺点是覆盖率下降，因此必须同时报告覆盖率和已接收样本准确率。

### 方案 B：独立的 packed expert

使用入口汇编、解压循环、动态解析、内存权限、CFG、节布局、导入和字符串训练单独的静态风险模型。

限制：

- 该模型判断的是壳/低层风险，不是 payload 自然语义；
- 必须收集大量有壳良性软件；
- 否则会退化成“有壳即恶意”；
- 评测必须分开报告 packed 和 unpacked。

### 方案 C：已知壳的静态解壳

对简单 UPX 或固定解压器，可用 IDAPython 识别 stub、恢复内存映像、重建入口，再重新分析。但通用静态解壳很难处理自修改、运行时 API、环境依赖和反调试。若严格不执行样本，不应把通用自动解壳作为第一阶段前置条件。

## 15. 训练数据构造与划分

### 15.1 不能直接把 5,000 个 BODMAS 全并入训练

当前有标签集是 747 良性、1,432 恶意；BODMAS 又增加 5,000 个恶意。直接合并会导致：

- 类别失衡；
- 来源与标签绑定；
- 家族和壳模板占据训练目标；
- 模型对 BODMAS 风格敏感，对真实未知来源泛化差。

### 15.2 去重和分组

建议先构造以下 group：

- 精确 SHA 去重；
- 导入/节布局近重复；
- 规范化伪代码 MinHash；
- 函数 embedding 聚类；
- 调用图/CFG 相似簇；
- 已知家族；
- 壳或编译模板簇；
- 数据来源。

同一近重复簇、同家族模板或同壳模板不能跨 train/test。

### 15.3 推荐划分

不是先随机 70/15/15 文件，而是先按 group 划分，再在组级别近似达到比例：

- train：允许多个已知来源和家族；
- validation：包含未见簇，用于阈值和拒判校准；
- test-family：家族 holdout；
- test-source：来源 holdout；
- test-packed：有壳单独测试；
- test-hard-benign：安装器、更新器、网络/管理工具和商业壳良性软件。

### 15.4 良性数据要求

必须增加真实“难良性”：

- 安装器和更新器；
- 使用 `VirtualProtect`、动态加载的合法程序；
- 网络客户端和远程管理工具；
- 压缩或加壳商业软件；
- 脚本宿主和打包器；
- 有签名和无签名程序。

`generated_win32_api` 可用于覆盖 API 组合，但不能作为主要良性来源，否则模型会学到生成器模板。

## 16. 训练目标和防捷径措施

基础目标为文件级 BCE/交叉熵。可增加：

- 质量 gate 的分类损失；
- 行为辅助头损失；
- 跨家族/来源的 supervised contrastive loss；
- 来源对抗头，降低 embedding 中的来源可分性；
- packed/unpacked 一致性或显式路由损失；
- attention 稀疏约束，使证据集中到少量函数。

建议按阶段增加，不能一开始把所有损失同时加入。第一版最重要的是 group split、MIL 和可靠度输出，而不是复杂损失函数。

## 17. 评测方案

不应只报告 accuracy 或 AUROC。建议报告：

- PR-AUC；
- ROC-AUC；
- TPR@1% FPR；
- FPR@固定 TPR；
- precision/recall/F1；
- Expected Calibration Error；
- 拒判覆盖率；
- selective risk：只对高可靠度样本判断时的错误率；
- packed/unpacked、x86/x64、不同来源、不同家族分别统计。

需要做的对照和消融：

1. 仅 IDA 结构/API 的 LightGBM 或 MLP 基线；
2. 仅伪代码编码器 + MIL；
3. 语义 + IDA 全局特征；
4. 加调用图；
5. 随机文件切分与 group holdout 的差距；
6. 去掉 API 名、去掉字符串、去掉伪代码分别测试；
7. packed expert 开启/关闭；
8. 不同函数选择数量 16/32/48 的成本与效果。

如果随机切分很高、source/family holdout 明显下降，应优先判断存在数据捷径，而不是继续扩大模型。

## 18. 推荐实施顺序

### 阶段 0：恢复稳定的 IDA 批处理环境

- 用一个已成功的 BODMAS 样本做健康检查；
- 单 worker 运行，确认日志和 JSON 能创建；
- 再测试一个本地良性样本；
- 检查许可、残留锁、杀毒/文件访问和命令行启动差异；
- 确认稳定后再开启并发。

### 阶段 1：本地有标签集提取

- 对 `dataset.csv` 校验路径、SHA、PE 架构；
- 跑 IDA 质量 gate 和结构提取；
- 先限制每文件 32--48 个函数；
- 记录超时、失败、反编译覆盖率；
- 不把工具故障误当成样本质量标签。

### 阶段 2：数据审计和轻量基线

- 精确/近重复审计；
- 按来源、家族、壳簇建立 group；
- 训练 IDA 结构/API 基线；
- 检查来源泄漏；
- 建立可信的验证/测试集。

### 阶段 3：语义 MIL 模型

- 伪代码规范化；
- 缓存函数级 encoder embedding；
- 训练 attention MIL；
- 融合全局 IDA 特征；
- 输出函数级证据和可靠度。

### 阶段 4：扩展 BODMAS 和有壳分支

- 对 BODMAS 按家族、壳状态、近重复簇分层采样；
- 先加入可语义分析的 BODMAS；
- 单独构建 packed expert；
- 收集有壳难良性；
- 最后评估是否值得实现特定壳的静态解壳。

## 19. 可复现命令

### 19.1 审计 BODMAS

```powershell
python model2\repair_bodmas_pe_headers.py audit `
  --root D:\bodmas_malware_dataset_batches `
  --batches 1-5
```

### 19.2 生成修复副本

```powershell
python model2\repair_bodmas_pe_headers.py repair `
  --root D:\bodmas_malware_dataset_batches `
  --output-root D:\bodmas_malware_dataset_batches_ida `
  --batches 1-5 `
  --workers 4
```

### 19.3 全量静态筛查

```powershell
python model2\static_triage.py `
  --root D:\bodmas_malware_dataset_batches_ida `
  --manifest D:\bodmas_malware_dataset_batches_ida\repair_manifest.csv `
  --output model2\bodmas_static_triage_5000.csv `
  --workers 8
```

### 19.4 IDA 选择集批处理

```powershell
python model2\run_ida_batch.py `
  --ida 'E:\Appself\IDA Pro-v9.0 RC1-Windows\IDA Pro-v9.0 RC1-Windows\idat.exe' `
  --extractor model2\ida_extract_sample.py `
  --selection model2\ida_pilot_selection.csv `
  --output-root D:\bodmas_ida_analysis\pilot `
  --timeout 180 `
  --max-functions 48 `
  --workers 2
```

## 20. 当前产物清单

| 文件 | 用途 |
|---|---|
| [`1.md`](1.md) | 搜集到的相关论文链接；当前存在中文编码显示问题，尚未作为实验依据系统复核 |
| [`repair_bodmas_pe_headers.py`](repair_bodmas_pe_headers.py) | 非破坏性修复 BODMAS Machine 字段 |
| [`test_repair_bodmas_pe_headers.py`](test_repair_bodmas_pe_headers.py) | PE 修复脚本测试 |
| [`BODMAS_REPAIR.md`](BODMAS_REPAIR.md) | 修复脚本说明 |
| [`static_triage.py`](static_triage.py) | 全量 PE 快速筛查 |
| [`bodmas_static_triage_5000.csv`](bodmas_static_triage_5000.csv) | 5,000 个样本的静态筛查结果 |
| [`ida_extract_sample.py`](ida_extract_sample.py) | IDA 9/Hex-Rays 单样本 JSON 提取 |
| [`run_ida_batch.py`](run_ida_batch.py) | IDA 批处理、超时和续跑 |
| [`ida_pilot_selection.csv`](ida_pilot_selection.csv) | BODMAS 代表样本选择清单 |
| [`ida_pilot_results.csv`](ida_pilot_results.csv) | 15 个 IDA 试点结果汇总 |
| [`local_ida_pilot_selection.csv`](local_ida_pilot_selection.csv) | 本地良性/恶意对照选择清单 |
| [`BODMAS_SAMPLE_FINDINGS.md`](BODMAS_SAMPLE_FINDINGS.md) | BODMAS 样本阶段性结论 |
| `D:\bodmas_malware_dataset_batches_ida\repair_manifest.csv` | 修复记录、架构和哈希映射 |
| `D:\bodmas_ida_analysis\pilot\json` | IDA 试点逐样本 JSON |
| `D:\bodmas_ida_analysis\pilot\logs` | IDA 试点日志 |

## 21. 已作出的决策

- 原始/消毒样本不覆盖，只生成修复副本；
- Machine 按 PE32/PE32+ 推断；
- `Subsystem=0` 默认保留；
- 不执行样本，只做静态分析；
- 第一版采用函数级表示，不拼接整文件；
- 第一版采用文件级 MIL，不给所有函数硬赋恶意标签；
- 第一版优先无壳/可可靠反编译样本；
- 有壳样本进入单独路由或拒判；
- 先做轻量结构基线，再做语义模型；
- 评测按来源、家族和近重复簇分组；
- `model1` 不处理。

## 22. 尚未完成

- 尚未跑完本地 2,179 条有标签样本的 IDA 提取；
- 尚未定位本地对照组 IDA 启动前挂起原因；
- 尚未完成全数据近重复/壳簇审计；
- 尚未建立可靠的 group holdout；
- 尚未训练任何恶意/良性模型；
- 尚未人工标注足够的 `semantic/packed_stub/unusable` 质量真值；
- 尚未收集足够的有壳难良性样本；
- 尚未实现伪代码规范化器、MIL 聚合器和证据输出；
- 尚未验证论文清单中的方案与当前数据的可复现性。

## 23. 当前推荐的最小可行版本

如果现在开始实现，最稳妥的 MVP 是：

1. 修复 IDA 批处理稳定性；
2. 只接收 quality gate 判定为 `semantic` 的样本；
3. 每个 PE 选择最多 32 个函数；
4. 使用约 125M 参数的代码/自然语言编码器；
5. 使用 attention MIL 聚合函数；
6. 融合少量 IDA 全局结构特征；
7. 输出恶意概率、分析可靠度和 top evidence functions；
8. 对 packed/unusable 返回证据不足；
9. 使用 source/family/near-duplicate group holdout 评测。

这一版本覆盖率不会最高，但最能回答核心研究问题：模型是否真正理解了反编译伪代码中的恶意行为语义，而不是只识别壳、家族或数据来源。
