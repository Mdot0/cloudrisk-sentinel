# tests/test_risk_engine.py
# Assumes your function is named `compute_score` and lives in: app/risk_engine.py
# i.e., from app.risk_engine import compute_score

from app.risk_engine import compute_score


def test_zero_findings_pass():
    counts = {
        "dependencies": {"high": 0, "medium": 0, "low": 0},
        "container": {"high": 0, "medium": 0, "low": 0},
        "iac": {"high": 0, "medium": 0, "low": 0},
        "secrets": 0,
    }
    result = compute_score(counts, threshold=1)
    assert result["score"] == 0
    assert result["decision"] == "PASS"


def test_one_high_blocks_at_threshold_10():
    counts = {
        "dependencies": {"high": 1, "medium": 0, "low": 0},
        "container": {"high": 0, "medium": 0, "low": 0},
        "iac": {"high": 0, "medium": 0, "low": 0},
        "secrets": 0,
    }
    result = compute_score(counts, threshold=10)
    assert result["score"] == 10
    assert result["decision"] == "BLOCK"


def test_medium_and_low_score_correct():
    counts = {
        "dependencies": {"high": 0, "medium": 1, "low": 1},
        "container": {"high": 0, "medium": 0, "low": 0},
        "iac": {"high": 0, "medium": 0, "low": 0},
        "secrets": 0,
    }
    result = compute_score(counts, threshold=999)
    assert result["score"] == 6  # 5 + 1
    assert result["decision"] == "PASS"


def test_secret_penalty_applied_and_blocks():
    counts = {
        "dependencies": {"high": 0, "medium": 0, "low": 0},
        "container": {"high": 0, "medium": 0, "low": 0},
        "iac": {"high": 0, "medium": 0, "low": 0},
        "secrets": 1,
    }
    result = compute_score(counts, threshold=20)
    assert result["score"] == 50
    assert result["decision"] == "BLOCK"


def test_adds_across_categories():
    counts = {
        "dependencies": {"high": 1, "medium": 0, "low": 0},
        "container": {"high": 0, "medium": 2, "low": 0},
        "iac": {"high": 0, "medium": 0, "low": 3},
        "secrets": 0,
    }
    result = compute_score(counts, threshold=999)
    # score = (1*10) + (2*5) + (3*1) = 10 + 10 + 3 = 23
    assert result["score"] == 23
    assert result["decision"] == "PASS"
    assert result["breakdown"]["dependencies"]["score"] == 10
    assert result["breakdown"]["container"]["score"] == 10
    assert result["breakdown"]["iac"]["score"] == 3


def test_custom_weights_are_respected():
    counts = {
        "dependencies": {"high": 1, "medium": 1, "low": 1},
        "container": {"high": 0, "medium": 0, "low": 0},
        "iac": {"high": 0, "medium": 0, "low": 0},
        "secrets": 1,
    }
    weights = {"high": 100, "medium": 10, "low": 1, "secrets": 7}
    result = compute_score(counts, weights=weights, threshold=999999)
    # score = 1*100 + 1*10 + 1*1 + 1*7 = 118
    assert result["score"] == 118
    assert result["decision"] == "PASS"