from app.compliance.score import map_controls, compute_compliance
from app.compliance.rotation import get_rotation_checklist
from app.risk.heuristic import compute_risk


def f(i, sev, status="open", **kw):
    d = {"id": i, "severity": sev, "status": status, "type": "secret"}
    d.update(kw)
    return d


def test_map_controls_secret():
    assert map_controls({"type": "secret", "rule_id": "aws-access-token"}) == (["A07:2021"], ["V6.4.1"])


def test_map_controls_dependency():
    assert map_controls({"type": "dependency"}) == (["A06:2021"], ["V14.2.1"])


def test_empty_is_100():
    assert compute_compliance([])["score"] == 100


def test_one_critical():
    assert compute_compliance([f(1, "critical")])["score"] == 85


def test_fixed_and_false_positive_ignored():
    fs = [f(1, "critical", "fixed"), f(2, "high", "false_positive")]
    assert compute_compliance(fs)["score"] == 100


def test_needs_rotation_half_penalty():
    assert compute_compliance([f(1, "high", "needs_rotation")])["score"] == 96


def test_never_below_zero():
    assert compute_compliance([f(i, "critical") for i in range(10)])["score"] == 0


def test_python_repo_scenario():
    fs = [f(1, "critical"), f(2, "critical"), f(3, "high"),
          f(4, "high", "needs_rotation"), f(5, "high"), f(6, "critical")]
    assert compute_compliance(fs)["score"] == 35


def test_rotation_types():
    assert get_rotation_checklist({"type": "secret", "secret_masked": "AKIA****NRTB"})["secret_type"] == "aws"
    assert get_rotation_checklist({"type": "secret", "secret_masked": "ghp_****abcd"})["secret_type"] == "github"
    assert get_rotation_checklist({"type": "dependency"}) is None


def test_risk_ordering():
    clean = compute_risk({"gitignore_has_env": True, "has_precommit_secret_hook": True,
                          "contributor_count": 2, "commit_count_90d": 10}, [])
    medium = compute_risk({"gitignore_has_env": False, "has_precommit_secret_hook": False},
                          [f(1, "high")])
    risky = compute_risk({"env_file_tracked": True, "gitignore_has_env": False,
                          "has_precommit_secret_hook": False, "historical_secret_count": 2},
                         [f(1, "critical"), f(2, "critical"), f(3, "high"),
                          f(4, "critical", type="dependency"), f(5, "high", type="dependency")])
    assert clean["score"] < medium["score"] < risky["score"]
    assert risky["score"] <= 100
    assert all("contribution" in x for x in risky["factors"])