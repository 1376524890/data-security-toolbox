from app.services.algorithm_service import entropy, evaluate_model, monobit_test, randomness_report, runs_test


def test_entropy() -> None:
    assert entropy(b"\x00\x00\x00\x00") == 0.0
    assert entropy(b"\x00\x01\x02\x03") > 1.0


def test_randomness_tests() -> None:
    bits = [0, 1, 0, 1, 0, 1, 0, 1]
    assert monobit_test(bits)["result"] in {"Pass", "Fail"}
    assert runs_test(bits)["result"] in {"Pass", "Fail"}


def test_randomness_report() -> None:
    report = randomness_report(b"abc123")
    assert report["overall"] in {"Pass", "Fail"}
    assert report["tests"]["entropy"] > 0


def test_evaluate_model() -> None:
    X = [[0, 0], [0, 1], [10, 10], [11, 9], [1, 0], [0, 0], [10, 11], [9, 10]]
    y = [0, 0, 1, 1, 0, 0, 1, 1]
    result = evaluate_model(X, y)
    assert result["accuracy"] >= 0
    assert result["samples"] == 8

