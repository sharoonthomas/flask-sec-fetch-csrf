"""
Custom exceptions for flask-sec-fetch-csrf.
"""

from werkzeug.exceptions import Forbidden


class CSRFError(Forbidden):
    """Raise if the client sends invalid CSRF data with the request.

    Generates a 403 Forbidden response with the failure reason by default.
    Customize the response by registering a handler with
    :meth:`flask.Flask.errorhandler`.

    Why 403 Forbidden and not 400 Bad Request?

    A CSRF failure indicates the request was understood but the server
    refuses to authorize it due to origin validation failure. This is
    semantically different from a malformed request (400).

    See: https://stackoverflow.com/questions/23478370
    """

    description = "CSRF validation failed."
