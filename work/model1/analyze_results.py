"""Quick analysis of C: drive scan results at different thresholds."""
import csv
from collections import Counter
from pathlib import Path

RESULTS = Path("pe_model_output_no_debug/scan_c_results.csv")

results = []
with RESULTS.open("r", encoding="utf-8-sig") as f:
    for r in csv.DictReader(f):
        r["malware_probability"] = float(r["malware_probability"])
        results.append(r)

print(f"C: 盘成功预测的 PE 总数: {len(results)}")
print()
print(f"{'阈值':<10} {'判为恶意':<10} {'比率':<10}")
print("-" * 30)
for thresh in [0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]:
    count = sum(1 for r in results if r["malware_probability"] >= thresh)
    pct = count / len(results) * 100
    bar = "#" * (count // 30)
    print(f"{thresh:<10} {count:<10} {pct:>5.1f}%    {bar}")

# Top hits at 0.5
print()
print("=" * 60)
print("阈值 0.5 下 Top 40 命中:")
print("=" * 60)
hits_05 = [r for r in results if r["malware_probability"] >= 0.5]
hits_05.sort(key=lambda r: r["malware_probability"], reverse=True)

# Group by top-level directory
dirs = Counter()
for r in hits_05:
    path = r["path"]
    # Extract C:\XXX\YYY pattern
    parts = path.replace("\\", "/").split("/")
    if len(parts) >= 3:
        dirs[parts[1]] += 1
    elif len(parts) >= 2:
        dirs[parts[1]] += 1

print(f"阈值0.5命中: {len(hits_05)} 个")
print()
print("命中文件的主要来源目录(C:\\): ")
for d, c in dirs.most_common(15):
    print(f"  {c:>5}  C:\\{d}")

print()
for i, r in enumerate(hits_05[:40], 1):
    path = r["path"]
    if len(path) > 110:
        path = "..." + path[-107:]
    print(f"{i:>3}. [{r['malware_probability']:.6f}] {path}")
