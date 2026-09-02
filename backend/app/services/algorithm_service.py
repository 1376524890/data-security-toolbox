import hashlib
import math
import time
from collections import Counter
from typing import Any


def to_bits(data: bytes) -> list[int]:
    return [bit for byte in data for bit in ((byte >> shift) & 1 for shift in range(7, -1, -1))]


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def monobit_test(bits: list[int]) -> dict[str, float | str]:
    n = len(bits)
    if n == 0:
        return {"statistic": 0.0, "p_value": 0.0, "result": "Inconclusive"}
    ones = sum(bits)
    statistic = abs(ones - n / 2) / math.sqrt(n / 4)
    p_value = math.erfc(statistic / math.sqrt(2))
    return {"statistic": statistic, "p_value": p_value, "result": "Pass" if p_value >= 0.01 else "Fail"}


def runs_test(bits: list[int]) -> dict[str, float | str]:
    n = len(bits)
    if n < 2:
        return {"statistic": 0.0, "p_value": 0.0, "result": "Inconclusive"}
    ones = sum(bits)
    zeros = n - ones
    runs = sum(1 for i in range(1, n) if bits[i] != bits[i - 1]) + 1
    pi = ones / n
    if pi == 0 or pi == 1:
        return {"statistic": float("inf"), "p_value": 0.0, "result": "Fail"}
    expected = 1 + 2 * ones * zeros / n
    variance = (2 * ones * zeros * (2 * ones * zeros - n)) / (n * n * (n - 1))
    statistic = abs(runs - expected) / math.sqrt(variance) if variance > 0 else float("inf")
    p_value = math.erfc(statistic / math.sqrt(2))
    return {"statistic": statistic, "p_value": p_value, "result": "Pass" if p_value >= 0.01 else "Fail"}


def frequency_test(bits: list[int]) -> dict[str, float | str]:
    return monobit_test(bits)


def randomness_report(data: bytes) -> dict[str, Any]:
    bits = to_bits(data)
    tests = {
        "entropy": entropy(data),
        "monobit": monobit_test(bits),
        "runs": runs_test(bits),
        "frequency": frequency_test(bits),
    }
    overall = "Pass" if all(test["result"] == "Pass" for test in tests.values() if isinstance(test, dict)) else "Fail"
    return {"overall": overall, "tests": tests, "sample_bits": len(bits)}


def _nearest_centroid(X: list[list[float]], y: list[int], test_X: list[list[float]]) -> list[int]:
    classes = sorted(set(y))
    centroids = {cls: [0.0] * len(X[0]) for cls in classes}
    counts = Counter(y)
    for row, label in zip(X, y):
        for idx, value in enumerate(row):
            centroids[label][idx] += value
    for cls in classes:
        centroids[cls] = [value / counts[cls] for value in centroids[cls]]
    predictions = []
    for row in test_X:
        best = min(classes, key=lambda cls: sum((a - b) ** 2 for a, b in zip(row, centroids[cls])))
        predictions.append(best)
    return predictions


def evaluate_model(X: list[list[float]], y: list[int], test_ratio: float = 0.25) -> dict[str, Any]:
    if not X or not y or len(X) != len(y) or len(X) < 4:
        raise ValueError("需要至少 4 条带标签样本")
    split = max(1, int(len(X) * (1 - test_ratio)))
    train_X, test_X = X[:split], X[split:]
    train_y, test_y = y[:split], y[split:]
    if len(set(train_y)) < 2:
        raise ValueError("训练集至少需要两个类别")
    try:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.metrics import accuracy_score, classification_report
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(train_X, train_y)
        predictions = model.predict(test_X).tolist()
        report = classification_report(test_y, predictions, output_dict=True, zero_division=0)
        engine = "scikit-learn RandomForestClassifier"
    except ImportError:
        predictions = _nearest_centroid(train_X, train_y, test_X)
        report = {}
        engine = "nearest-centroid fallback"
    accuracy = sum(p == t for p, t in zip(predictions, test_y)) / max(len(test_y), 1)
    return {
        "engine": engine,
        "accuracy": accuracy,
        "samples": len(X),
        "train_samples": len(train_X),
        "test_samples": len(test_X),
        "report": report,
    }


def performance_test(data: bytes) -> dict[str, Any]:
    started = time.perf_counter()
    for _ in range(1000):
        hashlib.sha256(data).hexdigest()
    elapsed = time.perf_counter() - started
    return {"algorithm": "sha256", "iterations": 1000, "elapsed_seconds": elapsed, "ops_per_second": 1000 / max(elapsed, 1e-9)}

