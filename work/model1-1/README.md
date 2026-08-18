# model1-1: dike_batch 独立测试实验

本实验复用 `model1/pe_feature_model.py` 的特征与模型流程，但将数据划分从原来的按标签随机 60/40 切分，改为按 `source` 字段做源域留出：

- 训练集：所有 `source` 不以 `dike_batch` 开头的样本
- 测试集：所有 `source` 以 `dike_batch` 开头的样本

## no_debug 含义

代码中的 `--exclude-debug-directory` 是 no_debug 消融设置，具体效果：

1. 从数值特征中移除 `debug_directory_present`；
2. 同时清除分类特征 `directory_presence_pattern` 中编码 Debug Directory 的 bit，避免模型从目录位掩码中恢复该信号。

其余 5 个目录位保持不变。

## 运行命令

```bash
python work/model1-1/pe_feature_model.py \
  --csv dataset.csv \
  --output-dir work/model1-1/pe_model_output_no_debug \
  --exclude-debug-directory \
  --source-test-prefix dike_batch
```

在 Windows 环境下若 joblib 线程池创建失败，可在同一命令前设置：

```powershell
$env:LOKY_MAX_CPU_COUNT='1'
$env:OMP_NUM_THREADS='1'
```

## 数据划分

| 集合 | 数量 | benign | malware | 说明 |
|---|---:|---:|---:|---|
| 训练集 | 1254 | 551 | 703 | 不含 dike_batch |
| 测试集 | 925 | 196 | 729 | 全部为 dike_batch |
| 成功提取训练特征 | 1233 | 532 | 701 | 21 个解析失败 |
| 成功提取测试特征 | 918 | 189 | 729 | 7 个解析失败 |

## 结果（no_debug，主模型 HistGradientBoosting）

- 5 折 CV balanced accuracy：0.9771
- 测试集 balanced accuracy：0.8413
- 测试集 recall：1.0000
- 测试集 specificity：0.6825
- 测试集 F1：0.9605
- 测试集 ROC AUC：0.9610
- 测试集 PR AUC：0.9878

完整指标见 `pe_model_output_no_debug/test_metrics.csv`，交叉验证见 `pe_model_output_no_debug/cv_results.csv`。
