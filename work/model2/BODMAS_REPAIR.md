# BODMAS PE 头修复

`repair_bodmas_pe_headers.py` 用于让消毒后的 BODMAS 样本可被 IDA/Ghidra
无界面分析。它不会修改原始样本，只在另一个目录生成修复副本。

## 修复内容

- PE32：将清零的 COFF `Machine` 恢复为 `0x014c`（x86）。
- PE32+：将清零的 COFF `Machine` 恢复为 `0x8664`（x64）。
- 默认保留 `Subsystem=0`，因为原始值无法从消毒文件可靠还原。
- 如某个工具必须要求 Subsystem，可显式使用 `--subsystem gui`，但该值会在
  `repair_manifest.csv` 中标记为 synthetic，不能作为模型特征。

## 使用

只读审计：

```powershell
python model2\repair_bodmas_pe_headers.py audit `
  --root D:\bodmas_malware_dataset_batches `
  --batches 1-5
```

生成全部修复副本：

```powershell
python model2\repair_bodmas_pe_headers.py repair `
  --root D:\bodmas_malware_dataset_batches `
  --output-root D:\bodmas_malware_dataset_batches_ida `
  --batches 1-5 `
  --workers 4
```

可用 `--limit N` 做小规模测试。重复运行会验证并跳过已正确修复的文件；分批运行时
`repair_manifest.csv` 会按 `batch_id + dataset_sha256` 合并记录。

如果本地有原始 `bodmas_metadata.csv`，可加：

```powershell
--metadata D:\path\to\bodmas_metadata.csv
```

这样修复清单会同时带上 first-seen 时间戳，便于之后做时间切分。

## 哈希说明

文件名里的 SHA 是 BODMAS 数据集标识，并不等于消毒后文件的实际 SHA。修复清单分别记录：

- `dataset_sha256`：原数据集提供的样本标识；
- `input_sha256`：本地消毒样本的实际内容哈希；
- `repaired_sha256`：修复副本的实际内容哈希。

不要覆盖原始目录，也不要把修复后的哈希误当成原始样本哈希。
