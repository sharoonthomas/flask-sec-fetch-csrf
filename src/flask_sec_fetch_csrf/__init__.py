"""
flask-sec-fetch-csrf
====================

CSRF protection for Flask using the Sec-Fetch-Site header.

This extension provides CSRF protection by validating the Sec-Fetch-Site
header sent by modern browsers, with a fallback to Origin header validation
for older browsers. No tokens required.

Basic usage::

    from flask import Flask
    from flask_sec_fetch_csrf import SecFetchCSRF

    app = Flask(__name__)
    csrf = SecFetchCSRF(app)

Application factory pattern::

    from flask_sec_fetch_csrf import SecFetchCSRF

    csrf = SecFetchCSRF()

    def create_app():
        app = Flask(__name__)
        csrf.init_app(app)
        return app

:copyright: (c) 2025 Fulfil.IO Inc.
:license: BSD-3-Clause, see LICENSE for more details.
"""

__version__ = "0.1.0"

from .exceptions import CSRFError
from .extension import SecFetchCSRF

__all__ = [
    "SecFetchCSRF",
    "CSRFError",
]
