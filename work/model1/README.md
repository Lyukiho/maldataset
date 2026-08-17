# PE malware dataset

All files are handled using static operations only; samples are never executed or emulated.

## Labels

- `0`: benign
- `1`: malware

## Sources

- Existing trusted benign PE files in `benign/`
- DikeDataset-labeled PE files found in `batch1` through `batch10`
- VirusShare PE samples, statically extracted from password-protected ZIP files and labeled malware by source provenance
- Malware-Database samples promoted from `other_malware/`

Files are named by verified SHA256. The `.exe` or `.dll` extension is derived from the PE COFF characteristics, not the source filename. Invalid PE files, hash mismatches, missing labels, and label conflicts are excluded and recorded in `failures.csv`.

Current manifest: 2179 samples (747 benign, 1432 malware).

## Handcrafted PE Feature Model

`pe_feature_model.py` — 基于 11 个手工 PE 特征的恶意软件检测模型。详见 [pe_features.md](pe_features.md)。

### 运行

```bash
python pe_feature_model.py                          # 默认 60/40 随机切分，阈值 0.3
python pe_feature_model.py --train-ratio 0.7         # 自定义训练比例
python pe_feature_model.py --threshold 0.5           # 自定义决策阈值
python pe_feature_model.py --train-ratio 0.7 --threshold 0.5
python pe_feature_model.py --exclude-debug-directory --output-dir pe_model_output_no_debug
```

### 特征（11个）

**数值特征（10个）：** `section_entropy_max`, `section_max_raw_size`(sqrt), `nonstandard_section_name_count`, `standard_section_name_count`, `user32_minus_crt_import_count`, `debug_directory_present`, `entry_section_rwx`, `embedded_payload_ratio`, `timestamp_implausible`, `checksum_zero`

**分类特征（1个）：** `directory_presence_pattern`（6-bit 位掩码）

### 模型（5种）

Logistic Regression, Decision Tree, Extra Trees, HistGradientBoosting, MLP (small) — 5 折分层交叉验证选出主力模型。

### 当前表现

| 指标 | 测试集（n=864） | 外部验证 other_malware/（n=123，SHA256 去重后成功解析） |
|---|---|---|
| 主力模型 | HistGradientBoosting | 同 |
| 阈值 | 0.3 | 0.3 |
| Balanced Accuracy | 97.25% | —（全恶意，无良性对照） |
| 检出率 | 98.6%（564/572，FN=8） | 95.1%（117/123，FN=6） |
| 误报率 | 4.1%（12/292，FP=12） | — |
| 中位数概率 | — | 0.9959 |
| 平均概率 | — | 0.9187 |

外部验证检出率低于内部测试集。漏报样本在部分关键 PE 特征上更接近训练集中的良性样本，尤其是调试目录出现率较高，提示外部集与训练集之间存在分布偏移。

### Debug Directory 消融实验

`--exclude-debug-directory` 会移除显式特征 `debug_directory_present`，同时清除 `directory_presence_pattern` 中编码相同信息的 debug 位，其他 5 个目录位保持不变。实验使用与基线完全相同的数据切分、阈值和模型选择流程，产物保存在 `pe_model_output_no_debug/`。

| 指标 | 基线 | 移除 Debug Directory | 变化 |
|---|---:|---:|---:|
| 5 折 CV Balanced Accuracy | 97.03% | 96.50% | -0.52 pp |
| 测试集 Balanced Accuracy | 97.25% | 96.64% | -0.60 pp |
| 测试集检出率 | 98.60%（564/572） | 98.43%（563/572） | -0.17 pp |
| 测试集误报率 | 4.11%（12/292） | 5.14%（15/292） | +1.03 pp |
| 外部验证检出率 | 95.12%（117/123） | 95.93%（118/123） | +0.81 pp |

移除 Debug Directory 信息后，内部指标小幅下降，但外部验证反而少漏报 1 个样本。这说明该特征对当前内部数据划分有帮助，但不是模型不可替代的核心信号，并可能包含一定的数据来源或构建流程偏差。

### 输出目录 `pe_model_output/`

| 文件 | 说明 |
|---|---|
| `model.joblib` | 导出的主力模型（sklearn pipeline） |
| `test_metrics.csv` | 测试集各模型指标 |
| `cv_results.csv` | 5 折交叉验证结果 |
| `predictions.csv` | 测试集每个样本的预测概率 |
| `other_malware_predictions.csv` | 外部验证集预测结果 |
| `other_malware_failures.csv` | 外部验证集解析失败记录 |
| `other_malware_duplicates_removed.csv` | 外部验证集 SHA256 去重记录 |
| `other_malware_promoted.csv` | 移入训练数据集的 100 个外部样本记录 |
| `feature_importance.csv` | 排列重要性 |
| `train_features.csv` / `test_features.csv` | 提取的特征 |
| `failures.csv` | 解析失败的样本 |
| `*.png` | 6 张评估图表 |

### 外部验证集 `other_malware/`

129 个 SHA256 唯一的 PE 样本，来自 [Malware-Database](https://github.com/Endermanch/Malware-Database)，覆盖 Binder / Crypter / ExploitKit / Infector / Worm / Banking Malware / Botnet / Builder 等类别。其中 123 个成功解析并用于验证，6 个解析失败；另有 100 个样本已移入训练数据集。全部为恶意样本，用于检测模型是否过拟合训练分布。

## 特征统计 `pe_statistics/`

`pe_statistics.py` — 对训练集（前 70% 样本）提取 90+ 个 PE 特征并生成统计图表（分布、相关性、Cohen's d 等）。
