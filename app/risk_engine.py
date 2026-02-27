def compute_score(counts, weights=None, threshold=20):
    """
    Compute a risk score + PASS/BLOCK decision from scan finding counts.

    counts (recommended shape):
      {
        "dependencies": {"high": 2, "medium": 4, "low": 10},
        "container":     {"high": 0, "medium": 1, "low": 3},
        "iac":           {"high": 1, "medium": 0, "low": 2},
        "secrets": 0
      }

    weights (optional):
      {"high": 10, "medium": 5, "low": 1, "secrets": 50}

    threshold:
      score >= threshold => BLOCK
    """

    # 1) Default weights (only if not provided)
    if weights is None:
        weights = {"high": 10, "medium": 5, "low": 1, "secrets": 50}

    # 2) Categories/severities (scalable: add new categories later with no code change)
    categories = ["dependencies", "container", "iac"]
    severities = ["high", "medium", "low"]

    breakdown = {}
    total_score = 0

    # 3) Add up category scores
    for category in categories:
        cat_counts = counts.get(category, {}) or {}
        cat_score = 0
        for sev in severities:
            cat_score += int(cat_counts.get(sev, 0)) * int(weights.get(sev, 0))
        breakdown[category] = {
            "counts": {sev: int(cat_counts.get(sev, 0)) for sev in severities},
            "score": cat_score,
        }
        total_score += cat_score

    # 4) Secrets score (separate because it's not high/medium/low)
    secrets_count = int(counts.get("secrets", 0))
    secrets_score = secrets_count * int(weights.get("secrets", 0))
    breakdown["secrets"] = {"count": secrets_count, "score": secrets_score}
    total_score += secrets_score

    # 5) Decision
    decision = "BLOCK" if total_score >= int(threshold) else "PASS"

    # 6) Return a structured result (useful for API + CI logs)
    return {
        "score": total_score,
        "decision": decision,
        "threshold": int(threshold),
        "weights": weights,
        "breakdown": breakdown,
    }