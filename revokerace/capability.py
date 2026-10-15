"""Small authenticated capability fixture; not a production authorization protocol."""

import base64
import hashlib
import hmac

from .lab import canonical, fields, integer, read_json, text


def mint(key, subject, issued_at, expires_at):
    body = canonical(
        {"subject": subject, "issued_at": issued_at, "expires_at": expires_at}
    )
    signature = hmac.new(key, body, hashlib.sha256).digest()
    return (
        base64.urlsafe_b64encode(body).decode()
        + "."
        + base64.urlsafe_b64encode(signature).decode()
    )


def authenticate(key, token):
    if not isinstance(token, str) or len(token) > 4096:
        raise ValueError("Invalid capability envelope")
    try:
        raw, signed = token.split(".")
        body = base64.b64decode(raw, altchars=b"-_", validate=True)
        signature = base64.b64decode(signed, altchars=b"-_", validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("Malformed capability envelope") from exc
    expected = hmac.new(key, body, hashlib.sha256).digest()
    if not hmac.compare_digest(signature, expected):
        raise ValueError("Invalid capability signature")
    claims = read_json(body)
    fields(claims, ("subject", "issued_at", "expires_at"))
    text(claims["subject"], "subject")
    integer(claims["issued_at"], "issued_at", 0, 3600)
    integer(claims["expires_at"], "expires_at", 1, 7200)
    if claims["expires_at"] <= claims["issued_at"]:
        raise ValueError("Capability expiry must follow issuance")
    return claims
