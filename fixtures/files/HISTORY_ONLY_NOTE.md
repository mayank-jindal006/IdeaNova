# Finding 103 — history-only, no live file

`app/payment_config.py` (finding 103, Stripe key) does NOT exist in the current
working tree — per Section 6.3 it was committed then deleted, so gitleaks only
finds it scanning git history (commit `f4e5d6c`).

Per Section 6.2, `in_history_only: true` should force tier `flag_only`:
no `generate_fix()` edit is expected for this finding — only explanation +
rotation checklist. Saina, don't feed this one through the normal fix path;
use it to test that your tier logic correctly routes history-only findings
to `flag_only` instead of attempting an edit.

For reference, the deleted commit's content was:

```python
# app/payment_config.py (deleted in a later commit)
STRIPE_SECRET_KEY = "sk_test_FAKE4242424242424242424242"
```
