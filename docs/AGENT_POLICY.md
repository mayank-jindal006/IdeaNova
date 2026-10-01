# RepoGuard Agent Policy

1. The agent never merges. A human always merges.
   Why: an automatic change to the main branch has no one accountable for it.
2. The agent only pushes to branches named repoguard/fix-*.
   Why: it can never overwrite code on main or on someone else's branch.
3. The agent only handles secret findings.
   Why: it has been tested only on that task, so we do not let it touch other changes.
4. The agent makes at most 2 repair attempts, then stops and flags a human.
   Why: it cannot loop forever, so cost and risk stay bounded.
5. CI logs are redacted before they reach the LLM.
   Why: logs can contain secret values, which must not be sent to a third party.
6. Auto-fix is off by default. A repo owner has to turn it on.
   Why: teams should opt in to automation that changes their code.
7. Every step is recorded in an audit trail.
   Why: if something goes wrong, we can see what the agent did and when.