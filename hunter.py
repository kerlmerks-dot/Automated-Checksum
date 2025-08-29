import requests
import re
import time
from telegram import Update
from telegram.ext import Updater, CommandHandler, MessageHandler, Filters, CallbackContext

# =============================
# Security: Owner + Approved Users
# =============================
OWNER_ID = 1326014119  # <<< replace with your Telegram user ID
approved_users = set([OWNER_ID])  # approved usernames or IDs


def is_authorized(update: Update):
    user_id = update.message.from_user.id
    username = update.message.from_user.username
    if user_id == OWNER_ID:
        return True
    return (username and username.lower() in approved_users) or (user_id in approved_users)


def approve(update: Update, context: CallbackContext):
    user_id = update.message.from_user.id
    if user_id != OWNER_ID:
        update.message.reply_text("⛔ Only the bot owner can approve users.")
        return

    if not context.args:
        update.message.reply_text("⚠️ Usage: /approve @username")
        return

    username = context.args[0].lstrip("@").lower()
    approved_users.add(username)
    update.message.reply_text(f"✅ Approved user: @{username}")


def revoke(update: Update, context: CallbackContext):
    user_id = update.message.from_user.id
    if user_id != OWNER_ID:
        update.message.reply_text("⛔ Only the bot owner can revoke users.")
        return

    if not context.args:
        update.message.reply_text("⚠️ Usage: /revoke @username")
        return

    username = context.args[0].lstrip("@").lower()
    if username in approved_users:
        approved_users.remove(username)
        update.message.reply_text(f"❌ Revoked access for: @{username}")
    else:
        update.message.reply_text(f"⚠️ User @{username} is not approved.")


# =============================
# Payment Gateways & Captchas
# =============================
GATEWAYS = {
    "Stripe": ["stripe.com", "checkout.stripe.com", "js.stripe.com"],
    "PayPal": ["paypal.com", "paypalobjects.com", "www.paypal.com/sdk", "os_paypal", "c.paypal.com"],
    "Shopify": ["checkout.shopifycs.com", "cdn.shopify.com", "shopifycloud", "shopify-checkout-api-token", "powered by shopify"],
    "Adyen": ["adyen.com", "checkoutshopper-live.adyen.com", "adyenpayments"],
    "Braintree": ["braintreepayments.com", "braintreegateway.com", "js.braintreegateway.com", "braintree_nonce", "braintree_cc_type_cvv_div"],
    "Square": ["squareup.com", "squarecdn.com", "square.api"],
    "Authorize.Net": ["authorize.net", "authnet", "secure2.authorize.net"],
    "Worldpay": ["worldpay.com", "secure.worldpay.com"],
    "Moneris": ["moneris.com", "e-selectplus"],
    "Checkout.com": ["checkout.com", "pay.checkout.com"],
    "Razorpay": ["razorpay.com", "checkout.razorpay.com"],
    "PayU": ["payu.in", "secure.payu.com", "api.payu.com"],
    "Paytm": ["paytm.com", "securegw.paytm.in"],
    "Skrill": ["skrill.com", "api.skrill.com"],
    "Neteller": ["neteller.com"],
    "Alipay": ["alipay.com", "int.alipay.com"],
    "WeChat Pay": ["wx.tenpay.com", "wechatpay"],
    "UnionPay": ["unionpaysecure.com"],
    "Klarna": ["klarna.com", "x.klarnacdn.net"],
    "Afterpay": ["afterpay.com", "static.afterpay.com"],
    "Affirm": ["affirm.com", "cdn1.affirm.com"],
    "CyberSource": ["cybersource.com", "secureacceptance"],
    "BlueSnap": ["bluesnap.com", "payments.bluesnap.com"],
    "2Checkout / Verifone": ["2checkout.com", "verifone.cloud"],
    "Amazon Pay": ["pay.amazon.com", "payments.amazon.com"],
    "Google Pay": ["pay.google.com", "googleapis.com/pay"],
    "Apple Pay": ["apple.com/apple-pay", "applepay.cdn-apple.com"],
    "Revolut Pay": ["revolut.com/pay"],
    "Wise (TransferWise)": ["wise.com/payments"],
    "Zelle": ["zellepay.com"],
    "Venmo": ["venmo.com", "api.venmo.com"],
    "Sofort": ["sofort.com", "klarna.com/sofort"],
    "Giropay": ["giropay.de"],
    "iDEAL": ["ideal.nl", "ing.nl/ideal"],
    "Paysafe": ["paysafe.com", "hosted.paysafe.com"],
    "Mollie": ["mollie.com", "api.mollie.com"],
    "Barclaycard": ["barclaycard.co.uk", "secure.barclays.com"],
    "WooCommerce": [
        "woocommerce", "wc_checkout_params", "wc_cart_fragments",
        "woocommerce-cart", "woocommerce-checkout", "wp-content/plugins/woocommerce"
    ],
    "Blackbaud": ["blackbaud.com", "bbpsapi.blackbaud.com", "hostedpayments.blackbaud.com", "payment.blackbaudhosting.com", "app.blackbaud.com"],
}

CAPTCHAS = {
    "hCaptcha": ["hcaptcha.com/1/api.js", "h-captcha"],
    "reCAPTCHA": ["www.google.com/recaptcha", "g-recaptcha"],
    "Cloudflare Turnstile": ["challenges.cloudflare.com"],
    "Generic Captcha": ["captcha"],
}


# =============================
# Analyzer
# =============================
def analyze_url(url):
    start_time = time.time()

    urls_to_check = [url]
    # also check common payment paths
    paths = ["/cart", "/checkout", "/donate", "/payment", "/billing"]
    for p in paths:
        if url.endswith("/"):
            urls_to_check.append(url + p.lstrip("/"))
        else:
            urls_to_check.append(url + p)

    detected_gateways = set()
    detected_captchas = set()

    for check_url in urls_to_check:
        try:
            response = requests.get(check_url, timeout=12, headers={"User-Agent": "Mozilla/5.0"})
            content = response.text.lower()
        except Exception:
            continue

        # multi-gateway detection
        for name, keywords in GATEWAYS.items():
            for kw in keywords:
                core = kw.lower()
                if core in content or re.search(rf"[a-z0-9.-]*{re.escape(core)}", content):
                    detected_gateways.add(name)
                    break

        # multi-captcha detection
        for name, keywords in CAPTCHAS.items():
            for kw in keywords:
                if kw.lower() in content:
                    detected_captchas.add(name)
                    break

    gateways_result = ", ".join(sorted(detected_gateways)) if detected_gateways else "Unknown"
    captcha_result = ", ".join(sorted(detected_captchas)) if detected_captchas else "NO"

    elapsed = time.time() - start_time
    elapsed_str = f"{elapsed:.2f} seconds"

    fancy_output = (
        "┌─────────────💳─────────────┐\n"
        "     PAYMENT GATEWAY CHECKER\n"
        "└────────────────────────────┘\n"
        f"🌍 SITE     : {url}\n"
        f"🏦 GATEWAYS : {gateways_result}\n"
        f"🤖 CAPTCHA  : {captcha_result}\n"
        f"⏱️ Checked in: {elapsed_str}"
    )
    return fancy_output


# =============================
# Telegram Handlers
# =============================
def start(update: Update, context: CallbackContext):
    if not is_authorized(update):
        update.message.reply_text("⛔ Unauthorized user")
        return
    update.message.reply_text(
        "👋 Hello! Send me a website URL or upload a .txt file with links.\n"
        "I’ll check which payment gateway(s) & captcha the site is using."
    )


def handle_message(update: Update, context: CallbackContext):
    if not is_authorized(update):
        update.message.reply_text("⛔ Unauthorized user")
        return

    url = update.message.text.strip()
    if not url.startswith("http"):
        update.message.reply_text("⚠️ Please send a valid URL (must start with http/https).")
        return

    waiting_msg = update.message.reply_text("⏳ Processing... Please wait")
    result = analyze_url(url)
    waiting_msg.edit_text(result)


def handle_file(update: Update, context: CallbackContext):
    if not is_authorized(update):
        update.message.reply_text("⛔ Unauthorized user")
        return

    file = update.message.document.get_file()
    file_path = "urls.txt"
    file.download(file_path)

    waiting_msg = update.message.reply_text("⏳ Processing file... Please wait")

    results = []
    with open(file_path, "r") as f:
        for line in f:
            url = line.strip()
            if url.startswith("http"):
                results.append(analyze_url(url))

    final_output = "\n\n".join(results)
    waiting_msg.edit_text(final_output if final_output else "⚠️ No valid URLs found in file.")


# =============================
# Main Runner
# =============================
def main():
    TOKEN = "7959249526:AAGIVsGKYzdL4lgpVBKWqj1p6z9FRpBtLXE"
    updater = Updater(TOKEN, use_context=True)
    dp = updater.dispatcher

    dp.add_handler(CommandHandler("start", start))
    dp.add_handler(CommandHandler("approve", approve))
    dp.add_handler(CommandHandler("revoke", revoke))
    dp.add_handler(MessageHandler(Filters.text & ~Filters.command, handle_message))
    dp.add_handler(MessageHandler(Filters.document.mime_type("text/plain"), handle_file))

    updater.start_polling()
    updater.idle()


if __name__ == "__main__":
    main()
