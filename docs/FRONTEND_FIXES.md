# RepoGuard frontend compatibility fixes

The current frontend is a standalone mock prototype. It cannot consume the contract API without the following changes.

1. Replace `SystemDataContext` hardcoded repositories, secrets, vulnerabilities, PRs, integrations, and timers with an API client rooted at `/api`.
2. Use contract field names and values: `repo_id`, `file_path`, `commit_sha`, `fixed_version`, Finding `type` of `secret` or `dependency`, and contract finding statuses.
3. Add routes `/repos/:id` and `/findings/:id`; render the `GET /api/repos/{id}` and `GET /api/findings/{id}` responses.
4. Implement scan flow using `POST /api/repos/{id}/scan`, then poll `GET /api/scans/{id}` every two seconds until `done` or `failed`.
5. Render `GET /api/dashboard/summary` for totals, severity counts, score rows, and the seven-day trend.
6. Generate a fix through `POST /api/findings/{id}/fix`, show its explanation, validation and full-file edit replacements, then open a PR with `POST /api/fixes/{id}/open-pr`.
7. Send `POST /api/findings/{id}/feedback` for the existing false-positive action.
8. Remove unsupported product claims and UI: provider-side key rotation/revocation, Vault integration, secret injection, schedules, SOC2/ISO export, and non-Python/npm dependency scanning.
9. Replace every “Predictive Leak Forecast” / “predictive risk model” label with **Heuristic Risk Score** and render the returned factor breakdown.
10. Do not display raw secret values in source snippets, diffs, or state. Display `secret_masked` only.
