"""Sample emails for demo mode (raw RFC-822 text). All domains are fictional."""

def _mail(n, sender, subject, body):
    return (f"Message-ID: <demo-{n}@phishguard.local>\nFrom: {sender}\nTo: inbox@example.com\n"
            f"Subject: {subject}\nContent-Type: text/plain; charset=utf-8\n\n{body}\n")

SAMPLE_EMAILS = [
    _mail(1, "Priya Sharma <priya@college.example>", "Project review moved to Thursday",
          "Hi team,\n\nThe project review is now on Thursday at 3 pm in Lab 2. Please bring your "
          "progress slides. Agenda: https://docs.college.example/review-agenda\n\nThanks,\nPriya"),
    _mail(2, "PayPal Security <alert@paypal-secure-login.xyz>", "URGENT: Your account has been suspended",
          "Dear Customer,\n\nWe detected unauthorized access to your account. Your account will be "
          "suspended within 24 hours. Verify your password immediately:\n"
          "http://paypal-secure-login.xyz/verify/account?id=88213\n\nPayPal Security Team"),
    _mail(3, "Rahul Mehta (CEO) <ceo.rahul@gmail.example>", "Quick favour - confidential",
          "Hi,\n\nI'm in a meeting and can't talk. I need you to buy 5 gift cards for a client today "
          "and send me the codes. Keep this between us, it's a private matter and very urgent. "
          "I will refund you tonight."),
    _mail(4, "Campus IT Helpdesk <helpdesk@college.example>", "Wi-Fi maintenance on Saturday",
          "Dear students,\n\nCampus Wi-Fi will be unavailable on Saturday from 2 am to 4 am for "
          "scheduled maintenance. No action is needed from you.\n\nIT Helpdesk"),
    _mail(5, "Netflix Billing <billing@netflix-account-update.top>", "Payment failed - update your billing details",
          "Dear member, your payment was declined. Update your payment details now to avoid "
          "account termination: http://192.168.44.12/netflix/login or "
          "https://bit.ly/3xFakeLink . Final notice!"),
    _mail(6, "Alumni Office <alumni@college.example>", "Newsletter: October highlights",
          "Hello,\n\nRead our October newsletter for placement news, upcoming workshops and "
          "alumni meet details: https://www.college.example/newsletter/october\n\nRegards, Alumni Office"),
]
