# Examples

## Setup

Install the package in development mode:

```bash
pip install -e ..
```

## Running the Basic App

Start the Flask application:

```bash
flask --app basic_app run --debug
```

Open http://127.0.0.1:5000 in your browser. The form submits normally because it's a same-origin request.

## Testing CSRF Protection

To see the CSRF protection in action, you need to simulate a cross-site request. This requires serving an "attacker" page from a different origin.

### Step 1: Start the Flask app (port 5000)

```bash
flask --app basic_app run --debug
```

### Step 2: Start the attacker page (port 8000)

In a separate terminal, from this directory:

```bash
python -m http.server 8000
```

### Step 3: Test the attack

1. Open http://127.0.0.1:8000/attacker.html
2. Click "Claim Prize"
3. The request is blocked with **403 Forbidden**

The browser automatically sets `Sec-Fetch-Site: cross-site` because the page origin (port 8000) differs from the form target (port 5000).

## Testing with curl

```bash
# Same-origin request (allowed)
curl -X POST http://127.0.0.1:5000/transfer \
  -H "Sec-Fetch-Site: same-origin"

# Cross-site request (blocked)
curl -X POST http://127.0.0.1:5000/transfer \
  -H "Sec-Fetch-Site: cross-site"

# No headers (allowed - treated as non-browser client)
curl -X POST http://127.0.0.1:5000/transfer
```
