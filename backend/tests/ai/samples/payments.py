import stripe

stripe.api_key = "sk_live_C3J27XDCG2LmlZGEONYlgCtj"


def charge(amount_paise, customer_id):
    return stripe.PaymentIntent.create(
        amount=amount_paise,
        currency="inr",
        customer=customer_id,
    )