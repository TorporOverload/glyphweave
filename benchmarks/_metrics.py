"""IR-metric functions for search-accuracy benchmarking."""
from __future__ import annotations


def precision_at_k(retrieved: list[str], relevant: set[str], k: int) -> float:
    top = retrieved[:k]
    if not top:
        return 0.0
    return sum(1 for d in top if d in relevant) / len(top)


def recall_at_k(retrieved: list[str], relevant: set[str], k: int) -> float:
    if not relevant:
        return 0.0
    top = retrieved[:k]
    return sum(1 for d in top if d in relevant) / len(relevant)


def average_precision(retrieved: list[str], relevant: set[str]) -> float:
    if not relevant:
        return 0.0
    hits = 0
    score = 0.0
    for i, doc in enumerate(retrieved, start=1):
        if doc in relevant:
            hits += 1
            score += hits / i
    return score / len(relevant)


def f1(precision: float, recall: float) -> float:
    if precision + recall == 0:
        return 0.0
    return 2 * precision * recall / (precision + recall)


def interpolated_pr_curve(
    retrieved: list[str], relevant: set[str], points: int = 11
) -> list[tuple[float, float]]:
    """11-point interpolated precision at recall levels 0.0 .. 1.0."""
    if not relevant:
        return []
    recalls: list[float] = []
    precisions: list[float] = []
    hits = 0
    for i, doc in enumerate(retrieved, start=1):
        if doc in relevant:
            hits += 1
        recalls.append(hits / len(relevant))
        precisions.append(hits / i)
    curve: list[tuple[float, float]] = []
    for j in range(points):
        level = j / (points - 1)
        candidates = [p for p, r in zip(precisions, recalls) if r >= level]
        curve.append((level, max(candidates) if candidates else 0.0))
    return curve
