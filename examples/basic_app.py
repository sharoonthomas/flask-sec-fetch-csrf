"""
Basic Flask application with CSRF protection.

Run with:
    flask --app examples/basic_app run
"""
from flask import Flask, render_template_string

from flask_sec_fetch_csrf import SecFetchCSRF

app = Flask(__name__)
csrf = SecFetchCSRF(app)

FORM_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>CSRF Protected Form</title></head>
<body>
    <h1>Transfer Money</h1>
    <form method="POST" action="/transfer">
        <label>To: <input type="text" name="to"></label><br>
        <label>Amount: <input type="number" name="amount"></label><br>
        <button type="submit">Transfer</button>
    </form>
    {% if message %}
    <p>{{ message }}</p>
    {% endif %}
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(FORM_TEMPLATE)


@app.route("/transfer", methods=["POST"])
def transfer():
    # This endpoint is automatically protected by SecFetchCSRF
    # Cross-site requests will be rejected with 403 Forbidden
    return render_template_string(FORM_TEMPLATE, message="Transfer successful!")


if __name__ == "__main__":
    app.run(debug=True)
