# RepoGuard Agent Policy

These rules match CONTRACTS section 8.4. Owner: Rishika.

1. The agent never merges. A human always merges.
   Why: a change to the main branch should always have a person accountable for it.

2. The agent only pushes to the branch repoguard/fix-<finding_id>, never to any other branch.
   Why: it can never overwrite main or anyone else's work.

3. The agent only handles findings of type "secret". A fix marked flag_only is never opened as a PR.
   Why: the agent is tested only on secrets, and a flag_only fix means the code change is not safe to automate.

4. A repair may only change three files: the affected file, .env.example and .gitignore.
   Why: otherwise the agent could make CI pass by editing the tests or the workflow, which would hide a real problem.

5. The agent makes at most 2 repair attempts per fix (MAX_REPAIR_ATTEMPTS = 2), then stops and leaves it for a human.
   Why: it cannot loop forever, so cost and risk stay bounded.

6. CI logs are treated like code. Secrets are redacted before any log text is sent to the LLM, and at most the last 200 lines are used.
   Why: logs can contain secret values, which must not be sent to a third party, and shorter input limits leakage and cost.

7. Auto-fix is off by default for every repo (auto_fix_enabled = false). A repo owner has to turn it on.
   Why: teams should choose to let automation change their code.

8. Every agent step is recorded in the Agent activity timeline.
   Why: if something goes wrong, we can see what the agent did and when.