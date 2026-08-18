# model1-1 模型调用包

这是一个可单独分发使用的 PE 恶意软件静态检测模型调用包。

## 文件说明

| 文件 | 说明 |
|---|---|
| `model.joblib` | 训练好的 no_debug 模型，sklearn Pipeline |
| `predict_pe.py` | 模型调用示例 |
| `pe_feature_model.py` | 特征提取实现 |
| `requirements.txt` | Python 依赖 |

## 环境准备

建议使用 Python 3.11 及以上版本，并在安装依赖后运行：

```bash
pip install -r requirements.txt
```

## 模型调用

```bash
python predict_pe.py <path-to-pe-file>
```

示例输出：

```text
file: E:\malware\sample.exe
malware_probability: 0.999617
prediction: 1 (malware)
threshold: 0.3
```

其中：

- `malware_probability`：模型给出的恶意概率
- `prediction`：`1` 表示判定为恶意，`0` 表示判定为良性
- `threshold`：当前使用的决策阈值

脚本仅做静态 PE 特征提取，不会运行目标文件。

## 模型口径说明

该模型是 no_debug 版本，调用时已做对应处理：

- 移除数值特征 `debug_directory_present`
- 清除 `directory_presence_pattern` 中 Debug Directory 对应的 bit

## 简单 Python 调用

```python
from pathlib import Path
from predict_pe import predict_one

result = predict_one(Path("sample.exe"))
print(result["malware_probability"])
print(result["prediction"])
```
