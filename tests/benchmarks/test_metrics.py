from benchmarks import _metrics as M


def test_precision_recall_at_k():
    retrieved = ["a", "x", "b", "y", "c"]      # relevant: a,b,c,d
    relevant = {"a", "b", "c", "d"}
    assert M.precision_at_k(retrieved, relevant, 5) == 3 / 5
    assert M.recall_at_k(retrieved, relevant, 5) == 3 / 4
    assert M.precision_at_k(retrieved, relevant, 1) == 1.0


def test_average_precision():
    retrieved = ["a", "x", "b"]                # relevant a@1, b@3
    relevant = {"a", "b"}
    # (1/1 + 2/3) / 2
    assert abs(M.average_precision(retrieved, relevant) - (1.0 + 2 / 3) / 2) < 1e-9


def test_negative_query_metrics_are_zero_safe():
    assert M.recall_at_k(["a"], set(), 5) == 0.0
    assert M.average_precision(["a"], set()) == 0.0
    assert M.interpolated_pr_curve(["a"], set()) == []


def test_f1():
    assert M.f1(0.5, 0.5) == 0.5
    assert M.f1(0.0, 0.0) == 0.0
