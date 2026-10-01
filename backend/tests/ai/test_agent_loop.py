"""Tests for the agent loop (agent.py Part 2): handle_new_findings + handle_ci_result.

No database, no GitHub, no LLM: a tiny fake DB holds plain objects, and Yash's GitHub helpers,
generate_fix and repair_fix are replaced with fakes that record what the agent asked for.
"""
from types import SimpleNamespace

import pytest

from app import models
from app.ai import agent
from app.ai import fix as fix_module

FIXED_EDIT = {"file_path": "config.py", "original_content": "KEY = 'x'\n", "new_content": "KEY = os.getenv('K')\n"}


class FakeDB:
    def __init__(self):
        self.rows = {}
        self.added = []
        self.commits = self.rollbacks = 0

    def put(self, model, obj):
        self.rows[(model, obj.id)] = obj
        return obj

    def get(self, model, id_):
        return self.rows.get((model, id_))

    def add(self, obj):
        obj.id = 100 + len(self.added)
        self.added.append(obj)
        self.rows[(type(obj), obj.id)] = obj

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1

    def refresh(self, obj):
        pass


def make_finding(**kw):
    data = dict(id=1, repo_id=1, type="secret", rule_id="aws-access-token", title="AWS key", severity="critical",
                file_path="config.py", line=1, start_column=8, end_column=27, commit_sha="abc",
                secret_masked="AKIA****2EPF", package=None, ecosystem=None, installed_version=None,
                fixed_version=None, in_history_only=False, confidence=0.9, status="open",
                owasp_ids=["A07:2021"], asvs_ids=[], fixes=[])
    data.update(kw)
    return SimpleNamespace(**data)


@pytest.fixture
def world(monkeypatch):
    """Fake DB with repo 1 (auto-fix ON) + finding 1, fake GitHub, recorded agent_runs."""
    db = FakeDB()
    repo = db.put(models.Repo, SimpleNamespace(id=1, full_name="team/test-repo", auto_fix_enabled=True))
    finding = db.put(models.Finding, make_finding(repo=repo))
    runs, gh_calls = [], []

    def log(db_, repo_id, step, detail, finding_id=None, fix_id=None, attempt=0):
        runs.append((step, detail))

    def record(name, result=None):
        def fn(*args, **kwargs):
            gh_calls.append((name, args))
            if isinstance(result, Exception):
                raise result
            return result
        return fn

    gh = SimpleNamespace(
        clone_repo=record("clone_repo", "/fake/clone"),
        cleanup_clone=record("cleanup_clone"),
        open_fix_pr=record("open_fix_pr", ("https://github.com/team/test-repo/pull/7", 7)),
        get_branch_files=record("get_branch_files", {"config.py": "KEY = os.getenv('K')\n"}),
        push_fix_commit=record("push_fix_commit", "sha-new"),
        comment_on_pr=record("comment_on_pr"),
    )
    monkeypatch.setattr(agent, "_log", log)
    monkeypatch.setattr(agent, "_github", lambda: gh)
    monkeypatch.setattr(agent, "_read_repo", lambda clone, path: ("KEY = 'x'\n", ["config.py"], {}))
    monkeypatch.setattr(agent, "find_secrets", lambda path, content: [])
    return SimpleNamespace(db=db, repo=repo, finding=finding, runs=runs, gh=gh, gh_calls=gh_calls)


def steps(world):
    return [step for step, _ in world.runs]


def fake_fix(tier="pr_review"):
    edits = [] if tier == "flag_only" else [FIXED_EDIT]
    ok = tier != "flag_only"
    return lambda finding, content, repo_files, existing_files=None: {
        "finding_id": finding["id"], "explanation": {"what": "w", "why_dangerous": "d", "how_fixed": "h"},
        "edits": edits, "tier": tier,
        "validation": {"secret_removed": ok or None, "syntax_ok": ok or None, "notes": ["the AI service was not available."]}}


# ---------- handle_new_findings ----------

def test_new_secret_gets_fix_and_pr(world, monkeypatch):
    monkeypatch.setattr(fix_module, "generate_fix", fake_fix())
    agent.handle_new_findings(world.db, 1, [1])
    assert steps(world) == ["detected", "fix_generated", "pr_opened", "ci_pending"]
    fix = world.db.added[0]
    assert fix.tier == "pr_review" and fix.ci_status == "pending"
    assert ("open_fix_pr", (world.db, fix.id)) in world.gh_calls
    assert world.gh_calls[-1][0] == "cleanup_clone"          # clone always removed


def test_auto_fix_off_does_nothing(world, monkeypatch):
    world.repo.auto_fix_enabled = False
    monkeypatch.setattr(fix_module, "generate_fix", fake_fix())
    agent.handle_new_findings(world.db, 1, [1])
    assert world.runs == [] and world.gh_calls == []


def test_flag_only_is_skipped_without_pr(world, monkeypatch):
    monkeypatch.setattr(fix_module, "generate_fix", fake_fix("flag_only"))
    agent.handle_new_findings(world.db, 1, [1])
    assert steps(world) == ["detected", "fix_generated", "skipped"]
    assert "not available" in world.runs[-1][1]
    assert not any(name == "open_fix_pr" for name, _ in world.gh_calls)


@pytest.mark.parametrize("change", [dict(type="dependency"), dict(in_history_only=True), dict(status="pr_opened"),
                                    dict(repo_id=2), dict(fixes=[SimpleNamespace(pr_url="u", branch=None)])])
def test_findings_the_agent_must_ignore(world, monkeypatch, change):
    for key, value in change.items():
        setattr(world.finding, key, value)
    monkeypatch.setattr(fix_module, "generate_fix", fake_fix())
    agent.handle_new_findings(world.db, 1, [1])
    assert world.runs == [] and world.gh_calls == []


def test_too_many_findings_are_capped(world, monkeypatch):
    for i in range(2, 9):
        world.db.put(models.Finding, make_finding(id=i, line=i))
    monkeypatch.setattr(fix_module, "generate_fix", fake_fix())
    agent.handle_new_findings(world.db, 1, list(range(1, 9)))
    assert steps(world).count("pr_opened") == agent.MAX_AUTO_FIXES_PER_PUSH
    assert steps(world).count("skipped") == 8 - agent.MAX_AUTO_FIXES_PER_PUSH


def test_one_failure_does_not_stop_the_rest(world, monkeypatch):
    world.db.put(models.Finding, make_finding(id=2))
    results = iter([RuntimeError("boom"), None])

    def flaky(finding, *args, **kwargs):
        error = next(results)
        if error:
            raise error
        return fake_fix()(finding, *args, **kwargs)

    monkeypatch.setattr(fix_module, "generate_fix", flaky)
    agent.handle_new_findings(world.db, 1, [1, 2])
    assert "error" in steps(world) and "pr_opened" in steps(world)
    assert world.db.rollbacks == 1


def test_clone_failure_is_logged_not_raised(world, monkeypatch):
    world.gh.clone_repo = lambda name: (_ for _ in ()).throw(RuntimeError("no token"))
    monkeypatch.setattr(fix_module, "generate_fix", fake_fix())
    agent.handle_new_findings(world.db, 1, [1])
    assert steps(world)[-1] == "error"


# ---------- handle_ci_result ----------

@pytest.fixture
def open_fix(world):
    fix = SimpleNamespace(id=5, finding=world.finding, branch="repoguard/fix-1", pr_number=7, ci_status="pending",
                          repair_attempts=0, head_sha="sha-1", edits=[FIXED_EDIT])
    world.db.put(models.Fix, fix)
    return fix


LOG = "E   NameError: name 'os' is not defined\napp/config.py:1: NameError\n"
REPAIRED = {"finding_id": 1, "tier": "pr_review",
            "explanation": {"what": "CI failed: os not imported", "why_dangerous": "x", "how_fixed": "Added import os."},
            "edits": [{"file_path": "config.py", "original_content": "KEY = os.getenv('K')\n",
                       "new_content": "import os\nKEY = os.getenv('K')\n"}],
            "validation": {"secret_removed": True, "syntax_ok": True, "notes": []}}


def test_ci_success(world, open_fix):
    agent.handle_ci_result(world.db, 5, "success", "")
    assert open_fix.ci_status == "passed"
    assert steps(world) == ["ci_passed"]
    assert world.gh_calls == []                               # never merges, never pushes


def test_ci_failure_is_repaired_and_pushed(world, open_fix, monkeypatch):
    seen = {}

    def fake_repair(finding, files, ci_errors, repo_files):
        seen.update(files=files, errors=ci_errors)
        return REPAIRED
    monkeypatch.setattr(agent, "repair_fix", fake_repair)

    agent.handle_ci_result(world.db, 5, "failure", LOG)
    assert steps(world) == ["ci_failed", "repaired"]
    assert "NameError: name 'os' is not defined" in world.runs[0][1]
    assert "E   NameError: name 'os' is not defined" in seen["errors"]
    push = next(args for name, args in world.gh_calls if name == "push_fix_commit")
    assert push[:2] == ("team/test-repo", "repoguard/fix-1")
    assert open_fix.repair_attempts == 1 and open_fix.head_sha == "sha-new" and open_fix.ci_status == "pending"
    assert open_fix.edits[0]["new_content"] == "import os\nKEY = os.getenv('K')\n"
    assert open_fix.edits[0]["original_content"] == FIXED_EDIT["original_content"]   # diff vs default branch kept
    assert world.gh_calls[-1][0] == "comment_on_pr"


def test_gives_up_after_max_repairs(world, open_fix, monkeypatch):
    open_fix.repair_attempts = agent.MAX_REPAIR_ATTEMPTS
    monkeypatch.setattr(agent, "repair_fix", lambda *a: pytest.fail("must not repair again"))
    agent.handle_ci_result(world.db, 5, "failure", LOG)
    assert steps(world) == ["ci_failed", "gave_up"]
    comment = next(args for name, args in world.gh_calls if name == "comment_on_pr")
    assert "Needs human review" in comment[2]
    assert not any(name == "push_fix_commit" for name, _ in world.gh_calls)


def test_impossible_repair_gives_up(world, open_fix, monkeypatch):
    flag = dict(REPAIRED, tier="flag_only", edits=[],
                validation={"secret_removed": None, "syntax_ok": None,
                            "notes": ["the CI failure does not seem to be caused by this fix (missing package)."]})
    monkeypatch.setattr(agent, "repair_fix", lambda *a: flag)
    agent.handle_ci_result(world.db, 5, "failure", LOG)
    assert steps(world) == ["ci_failed", "repair_failed", "gave_up"]
    assert not any(name == "push_fix_commit" for name, _ in world.gh_calls)


def test_never_pushes_to_a_foreign_branch(world, open_fix, monkeypatch):
    open_fix.branch = "main"
    monkeypatch.setattr(agent, "repair_fix", lambda *a: REPAIRED)
    agent.handle_ci_result(world.db, 5, "failure", LOG)
    assert steps(world) == ["ci_failed", "error"]
    assert world.gh_calls == []


def test_cancelled_run_changes_nothing(world, open_fix):
    agent.handle_ci_result(world.db, 5, "cancelled", "")
    assert open_fix.ci_status == "pending" and steps(world) == ["error"]


def test_unknown_fix_is_ignored(world):
    agent.handle_ci_result(world.db, 999, "failure", LOG)
    assert world.runs == []


def test_secret_in_ci_log_never_reaches_agent_runs(world, open_fix, monkeypatch):
    monkeypatch.setattr(agent, "find_secrets", lambda path, content: ["sk_live_abcdefgh12345678"])
    monkeypatch.setattr(agent, "repair_fix", lambda *a: REPAIRED)
    agent.handle_ci_result(world.db, 5, "failure", 'E   ValueError: bad key sk_live_abcdefgh12345678\n')
    assert world.runs[0] == ("ci_failed", "CI failed: ValueError")
    assert all("sk_live" not in detail for _, detail in world.runs)
    push = next(args for name, args in world.gh_calls if name == "push_fix_commit")
    assert "sk_live" not in push[3]                          # commit message too

# ---------- integration: real models + real record_agent_run on SQLite ----------

@pytest.fixture
def real_db(monkeypatch):
    sqlalchemy = pytest.importorskip("sqlalchemy")
    from sqlalchemy.orm import sessionmaker
    from app.db.base import Base
    if not hasattr(models, "AgentRun"):
        pytest.skip("agent tables not in models yet")
    engine = sqlalchemy.create_engine("sqlite://")
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    repo = models.Repo(full_name="team/test-repo", default_branch="main", auto_fix_enabled=True)
    db.add(repo)
    db.flush()
    scan = models.Scan(repo_id=repo.id, trigger=models.ScanTrigger.push, status=models.ScanStatus.done)
    db.add(scan)
    db.flush()
    finding = models.Finding(scan_id=scan.id, repo_id=repo.id, fingerprint="f1", type=models.FindingType.secret,
                             rule_id="aws-access-token", title="AWS key", severity=models.Severity.critical,
                             file_path="config.py", line=1, start_column=8, end_column=27,
                             secret_masked="AKIA****2EPF", confidence=0.9)
    db.add(finding)
    db.commit()
    monkeypatch.setattr(agent, "_read_repo", lambda clone, path: ("KEY = 'x'\n", ["config.py"], {}))
    monkeypatch.setattr(agent, "find_secrets", lambda path, content: [])
    yield db, repo, finding
    db.close()


def _real_gh(gh_calls):
    def open_fix_pr(db, fix_id):   # like Yash's: sets branch/head_sha, commits, returns the Fix
        fix = db.get(models.Fix, fix_id)
        fix.branch, fix.pr_url, fix.pr_number = f"repoguard/fix-{fix.finding_id}", "https://pr/7", 7
        fix.head_sha = "sha-1"
        db.commit()
        return fix
    return SimpleNamespace(
        clone_repo=lambda name: "/fake", cleanup_clone=lambda path: None, open_fix_pr=open_fix_pr,
        get_branch_files=lambda name, branch, paths: {p: "KEY = os.getenv('K')\n" for p in paths},
        push_fix_commit=lambda *a: gh_calls.append(("push", a)),     # returns None, like Yash's
        comment_on_pr=lambda *a: gh_calls.append(("comment", a)))


def test_full_loop_on_real_models(real_db, monkeypatch):
    db, repo, finding = real_db
    gh_calls = []
    monkeypatch.setattr(agent, "_github", lambda: _real_gh(gh_calls))
    monkeypatch.setattr(fix_module, "generate_fix", fake_fix())
    monkeypatch.setattr(agent, "repair_fix", lambda *a: REPAIRED)

    agent.handle_new_findings(db, repo.id, [finding.id])
    fix = db.query(models.Fix).one()
    assert fix.branch == f"repoguard/fix-{finding.id}" and fix.ci_status == "pending"

    agent.handle_ci_result(db, fix.id, "failure", LOG)
    agent.handle_ci_result(db, fix.id, "success", "")
    db.expire_all()
    fix = db.get(models.Fix, fix.id)
    assert fix.ci_status == "passed" and fix.repair_attempts == 1
    runs = [getattr(r.step, "value", r.step) for r in db.query(models.AgentRun).order_by(models.AgentRun.id)]
    assert runs == ["detected", "fix_generated", "pr_opened", "ci_pending", "ci_failed", "repaired", "ci_passed"]
    assert db.query(models.AgentRun).filter_by(step="pr_opened").one().detail == "https://pr/7"
    assert [name for name, _ in gh_calls] == ["push", "comment"]

@pytest.mark.parametrize("signature", ["contract", "yash"])
def test_log_works_with_both_record_agent_run_signatures(monkeypatch, signature):
    """record_agent_run's argument order changed once; the agent passes keywords only."""
    import sys
    import types
    seen = {}
    if signature == "contract":
        def record(db, repo_id, step, detail, finding_id=None, fix_id=None, attempt=0):
            seen.update(step=step, detail=detail, attempt=attempt)
    else:
        def record(db, repo_id, finding_id=None, fix_id=None, step="", status="", detail=""):
            seen.update(step=step, detail=detail, status=status)
    monkeypatch.setitem(sys.modules, "app.agent_log", types.SimpleNamespace(record_agent_run=record))
    agent._log(FakeDB(), 1, "gave_up", "CI still fails", finding_id=1, fix_id=2, attempt=2)
    assert seen["step"] == "gave_up" and seen["detail"] == "CI still fails"
    assert seen.get("attempt", 2) == 2 and seen.get("status", "failed") == "failed"