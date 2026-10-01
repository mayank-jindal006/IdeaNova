repoguard-test-python
1. app/config.py L3  AWS access key ID     aws-access-token
2. app/config.py L4  AWS secret key        generic-api-key
3. app/db.py L5      DB password           generic-api-key
4. app/payments.py   Stripe-style key      generic-api-key (history-only)
Deps: Flask 0.12.2, PyYAML 5.1