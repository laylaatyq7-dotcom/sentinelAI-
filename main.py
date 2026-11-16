"""SentinelAI API: a single-file FastAPI service (secrets/PII scanner and HTTP header analyzer).

Run locally:      uvicorn main:app --reload
Render start cmd: uvicorn main:app --host 0.0.0.0 --port $PORT
"""
import hashlib
import hmac
import logging
import math
import os
import re
import time
import uuid
from bisect import bisect_right
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Callable, Literal, Optional

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.middleware.cors import CORSMiddleware

app
VERSION = "1.0.0"

# ============================ SECTION: settings ============================ #
# All configuration comes from environment variables (set them in the Render dashboard).
ENVIRONMENT = os.getenv("ENVIRONMENT", "development").lower()
# Secret that RapidAPI adds to every proxied request (header X-RapidAPI-Proxy-Secret).
RAPIDAPI_PROXY_SECRET = os.getenv("RAPIDAPI_PROXY_SECRET", "").strip()
MAX_CONTENT_CHARS = int(os.getenv("MAX_CONTENT_CHARS", "200000"))
MAX_BODY_BYTES = int(os.getenv("MAX_BODY_BYTES", "500000"))
ENABLE_DOCS = os.getenv("ENABLE_DOCS", "true").lower() == "true"
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("sentinelai")


# ============================ SECTION: scanner ============================= #
ENGINE_VERSION = "1.0.0"

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SEVERITY_WEIGHT = {"critical": 40, "high": 20, "medium": 8, "low": 2, "info": 0}
MAX_MATCHES_PER_RULE = 2000  # hard cap so a hostile payload cannot make one rule run away


# --------------------------------------------------------------------------- #
# Validators (reduce false positives)
# --------------------------------------------------------------------------- #
def luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def valid_card(raw: str) -> bool:
    digits = re.sub(r"\D", "", raw)
    return (
        13 <= len(digits) <= 19
        and digits[0] in "3456"
        and len(set(digits)) > 1
        and luhn_ok(digits)
    )


def valid_ssn(raw: str) -> bool:
    area, group, serial = raw.split("-")
    return area not in ("000", "666") and not area.startswith("9") and group != "00" and serial != "0000"


def valid_iban(raw: str) -> bool:
    s = raw.replace(" ", "").upper()
    if not 15 <= len(s) <= 34:
        return False
    rearranged = s[4:] + s[:4]
    try:
        number = "".join(str(int(c, 36)) for c in rearranged)
    except ValueError:
        return False
    return int(number) % 97 == 1


_PLACEHOLDER_HINTS = (
    "example", "your", "changeme", "change_me", "placeholder", "dummy", "sample",
    "xxxx", "****", "<", ">", "${", "{{", "redacted", "todo",
)


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def looks_like_real_secret(value: str) -> bool:
    low = value.lower()
    if any(h in low for h in _PLACEHOLDER_HINTS):
        return False
    return len(set(value)) > 4 and shannon_entropy(value) >= 3.0


def not_placeholder(value: str) -> bool:
    low = value.lower()
    return not any(h in low for h in _PLACEHOLDER_HINTS)


# --------------------------------------------------------------------------- #
# Masking (what the API returns instead of the raw value)
# --------------------------------------------------------------------------- #
def mask_secret(v: str) -> str:
    n = len(v)
    if n <= 8:
        return "*" * n
    keep = 4 if n >= 20 else 2
    return v[:keep] + "*" * min(n - 2 * keep, 16) + v[-keep:]


def mask_email(v: str) -> str:
    local, _, domain = v.partition("@")
    return local[:2] + "***@" + domain


def mask_card(v: str) -> str:
    d = re.sub(r"\D", "", v)
    return "*" * (len(d) - 4) + d[-4:]


def mask_ssn(v: str) -> str:
    return "***-**-" + v[-4:]


def mask_iban(v: str) -> str:
    s = v.replace(" ", "")
    return s[:4] + "*" * (len(s) - 6) + s[-2:]


def keep_as_is(v: str) -> str:  # for markers that are not themselves secret, e.g. a PEM header line
    return v


# --------------------------------------------------------------------------- #
# Rules
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Rule:
    id: str
    category: str  # "secrets" or "pii"
    severity: str
    title: str
    pattern: re.Pattern
    recommendation: str
    group: int = 0
    validator: Optional[Callable[[str], bool]] = None
    mask: Callable[[str], str] = mask_secret


_ROTATE = "Revoke this credential immediately, issue a new one and remove it from the source."
_I = re.IGNORECASE

RULES: list[Rule] = [
    Rule("private_key", "secrets", "critical", "Private key block",
         re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"),
         "Remove the key from the content, treat it as compromised and generate a new key pair.", mask=keep_as_is),
    Rule("aws_access_key_id", "secrets", "critical", "AWS access key ID",
         re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), _ROTATE),
    Rule("aws_secret_access_key", "secrets", "critical", "AWS secret access key",
         re.compile(r"aws_?secret_?access_?key\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})[\"']?", _I), _ROTATE, group=1),
    Rule("github_token", "secrets", "critical", "GitHub token",
         re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"), _ROTATE),
    Rule("stripe_live_key", "secrets", "critical", "Stripe live API key",
         re.compile(r"\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b"), _ROTATE),
    Rule("slack_token", "secrets", "high", "Slack token",
         re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), _ROTATE),
    Rule("slack_webhook", "secrets", "high", "Slack webhook URL",
         re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{20,}"),
         "Delete and recreate the webhook; anyone with the URL can post to your workspace."),
    Rule("google_api_key", "secrets", "high", "Google API key",
         re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "Restrict or rotate the key in the Google Cloud console."),
    Rule("anthropic_api_key", "secrets", "high", "Anthropic API key",
         re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"), _ROTATE),
    Rule("openai_api_key", "secrets", "high", "OpenAI API key",
         re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}\b"), _ROTATE),
    Rule("sendgrid_api_key", "secrets", "high", "SendGrid API key",
         re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"), _ROTATE),
    Rule("npm_token", "secrets", "high", "npm access token",
         re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), _ROTATE),
    Rule("credentials_in_url", "secrets", "high", "Password embedded in a connection string or URL",
         re.compile(r"\b[a-z][a-z0-9+.\-]{1,30}://[^\s:/@\"']{1,100}:([^\s@/\"']{3,100})@[^\s\"']{1,255}", _I),
         "Move credentials to a secret manager or environment variable and rotate the password.",
         group=1, validator=not_placeholder),
    Rule("jwt", "secrets", "medium", "JSON Web Token",
         re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"),
         "Make sure the token is expired or revoked and do not log or commit tokens."),
    Rule("generic_secret_assignment", "secrets", "high", "Hard-coded secret in an assignment",
         re.compile(
             r"\b(?:api[_\-]?key|apikey|secret(?:[_\-]?key)?|access[_\-]?token|auth[_\-]?token|"
             r"client[_\-]?secret|passwd|password|pwd)\b\s*[:=]\s*[\"']([^\"'\s]{8,200})[\"']", _I),
         "Load this value from a secret manager or environment variable instead of hard-coding it.",
         group=1, validator=looks_like_real_secret),
    # ---- PII ----
    Rule("credit_card", "pii", "high", "Payment card number",
         re.compile(r"\b(?:\d[ -]?){12,18}\d\b"),
         "Do not store or transmit full card numbers; use a tokenizing payment provider.",
         validator=valid_card, mask=mask_card),
    Rule("us_ssn", "pii", "high", "US Social Security number",
         re.compile(r"(?<![\d-])\d{3}-\d{2}-\d{4}(?![\d-])"),
         "Remove or tokenize the number; restrict who can access this data.",
         validator=valid_ssn, mask=mask_ssn),
    Rule("iban", "pii", "medium", "IBAN (bank account number)",
         re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b"),
         "Remove or mask bank account numbers unless they are strictly required.",
         validator=valid_iban, mask=mask_iban),
    Rule("email_address", "pii", "low", "Email address",
         re.compile(r"\b[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,255}\.[A-Za-z]{2,24}\b"),
         "Confirm you have a lawful basis to process this personal data.", mask=mask_email),
]


# --------------------------------------------------------------------------- #
# Scanning
# --------------------------------------------------------------------------- #
@dataclass
class ScanResult:
    findings: list[dict]
    summary: dict
    lines: int
    chars: int


def _risk_level(by_severity: dict[str, int]) -> str:
    for sev in ("critical", "high", "medium", "low"):
        if by_severity.get(sev):
            return sev
    return "none"


def scan_content(content: str, checks: list[str], max_findings: int) -> ScanResult:
    line_starts = [0] + [m.end() for m in re.finditer("\n", content)]

    # 1) Collect candidate matches from every enabled rule.
    candidates: list[tuple[Rule, int, int, int, str]] = []
    for idx, rule in enumerate(RULES):
        if rule.category not in checks:
            continue
        count = 0
        for m in rule.pattern.finditer(content):
            value = m.group(rule.group)
            if rule.validator and not rule.validator(value):
                continue
            start, end = m.span(rule.group)
            candidates.append((rule, idx, start, end, value))
            count += 1
            if count >= MAX_MATCHES_PER_RULE:
                break

    # 2) Resolve overlaps: highest severity wins (ties: earlier position, then rule order).
    candidates.sort(key=lambda c: (-SEVERITY_RANK[c[0].severity], c[2], c[1]))
    starts: list[int] = []
    ends: list[int] = []
    accepted: list[tuple[Rule, int, int, str]] = []
    for rule, _idx, start, end, value in candidates:
        i = bisect_right(starts, start)
        if i > 0 and ends[i - 1] > start:
            continue
        if i < len(starts) and starts[i] < end:
            continue
        starts.insert(i, start)
        ends.insert(i, end)
        accepted.append((rule, start, end, value))

    # 3) Order for presentation: severity first, then position in the text.
    accepted.sort(key=lambda a: (-SEVERITY_RANK[a[0].severity], a[1]))

    by_severity = {s: 0 for s in SEVERITY_RANK}
    by_category = {"secrets": 0, "pii": 0}
    for rule, *_ in accepted:
        by_severity[rule.severity] += 1
        by_category[rule.category] += 1

    findings: list[dict] = []
    for n, (rule, start, _end, value) in enumerate(accepted[:max_findings], start=1):
        line = bisect_right(line_starts, start)
        findings.append({
            "id": f"F{n:04d}",
            "rule": rule.id,
            "category": rule.category,
            "title": rule.title,
            "severity": rule.severity,
            "line": line,
            "column": start - line_starts[line - 1] + 1,
            "match_preview": rule.mask(value),
            # One-way hash for de-duplicating secrets. Omitted for PII, whose small value space is guessable.
            "fingerprint": hashlib.sha256(value.encode("utf-8")).hexdigest()[:12] if rule.category == "secrets" else None,
            "recommendation": rule.recommendation,
        })

    risk_score = min(100, sum(SEVERITY_WEIGHT[r.severity] for r, *_ in accepted))
    summary = {
        "risk_score": risk_score,
        "risk_level": _risk_level(by_severity),
        "total_findings": len(accepted),
        "returned_findings": len(findings),
        "truncated": len(accepted) > len(findings),
        "by_severity": by_severity,
        "by_category": by_category,
    }
    return ScanResult(findings=findings, summary=summary, lines=len(line_starts), chars=len(content))

# ============================ SECTION: headers ============================= #
PENALTY = {"high": 20, "medium": 10, "low": 5, "info": 0}


def _grade(score: int) -> str:
    return "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"


def analyze_headers(headers: dict[str, str]) -> dict:
    h = {k.strip().lower(): v.strip() for k, v in headers.items()}
    findings: list[dict] = []
    passed: list[str] = []

    def add(check: str, header: str | None, title: str, severity: str, detail: str, rec: str) -> None:
        findings.append({
            "id": f"H{len(findings) + 1:03d}", "check": check, "header": header,
            "title": title, "severity": severity, "detail": detail, "recommendation": rec,
        })

    # HSTS
    hsts = h.get("strict-transport-security")
    if hsts is None:
        add("hsts", "Strict-Transport-Security", "HSTS header is missing", "high",
            "Browsers may connect over plain HTTP and are exposed to downgrade attacks.",
            "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.")
    else:
        m = re.search(r"max-age\s*=\s*(\d+)", hsts, re.I)
        if not m or int(m.group(1)) < 15552000:
            add("hsts", "Strict-Transport-Security", "HSTS max-age is too short", "medium",
                f"Value is '{hsts[:120]}'; at least 6 months (15552000 seconds) is recommended.",
                "Use max-age=31536000 or higher.")
        else:
            passed.append("hsts")

    # Content-Security-Policy
    csp = h.get("content-security-policy")
    if csp is None:
        add("csp", "Content-Security-Policy", "Content-Security-Policy is missing", "high",
            "Without a CSP, injected scripts run with full page privileges.",
            "Define a CSP that limits script, style and frame sources.")
    else:
        weak = [t for t in ("'unsafe-inline'", "'unsafe-eval'") if t in csp.lower()]
        if re.search(r"(?:^|;)\s*(?:default|script)-src[^;]*\s\*(?:\s|;|$)", csp, re.I):
            weak.append("wildcard source")
        if weak:
            add("csp_weak", "Content-Security-Policy", "Content-Security-Policy contains weak directives", "medium",
                "Found: " + ", ".join(weak) + ".", "Remove unsafe-inline/unsafe-eval and wildcard sources; use nonces or hashes.")
        else:
            passed.append("csp")

    # MIME sniffing
    xcto = h.get("x-content-type-options")
    if xcto is None or xcto.lower() != "nosniff":
        add("nosniff", "X-Content-Type-Options", "MIME sniffing protection is missing", "medium",
            "Browsers may treat responses as a different content type than declared.",
            "Send 'X-Content-Type-Options: nosniff'.")
    else:
        passed.append("nosniff")

    # Clickjacking
    xfo = h.get("x-frame-options", "").upper()
    if xfo not in ("DENY", "SAMEORIGIN") and "frame-ancestors" not in (csp or "").lower():
        add("clickjacking", "X-Frame-Options", "Clickjacking protection is missing", "medium",
            "The page can be embedded in a hostile site's frame.",
            "Send 'X-Frame-Options: DENY' or a CSP 'frame-ancestors' directive.")
    else:
        passed.append("clickjacking")

    # Referrer policy
    rp = h.get("referrer-policy")
    if rp is None:
        add("referrer_policy", "Referrer-Policy", "Referrer-Policy is missing", "low",
            "Full URLs may leak to third-party sites.", "Send 'Referrer-Policy: strict-origin-when-cross-origin'.")
    elif rp.lower() in ("unsafe-url", "no-referrer-when-downgrade"):
        add("referrer_policy", "Referrer-Policy", "Referrer-Policy leaks full URLs", "low",
            f"Value is '{rp}'.", "Use 'strict-origin-when-cross-origin' or stricter.")
    else:
        passed.append("referrer_policy")

    # Permissions policy
    if "permissions-policy" not in h:
        add("permissions_policy", "Permissions-Policy", "Permissions-Policy is missing", "low",
            "Browser features such as camera and geolocation are not explicitly restricted.",
            "Send a Permissions-Policy that disables features you do not use.")
    else:
        passed.append("permissions_policy")

    # Cross-origin isolation (informational)
    if "cross-origin-opener-policy" not in h:
        add("coop", "Cross-Origin-Opener-Policy", "Cross-Origin-Opener-Policy is not set", "info",
            "Optional hardening that isolates your page from cross-origin windows.",
            "Consider 'Cross-Origin-Opener-Policy: same-origin'.")
    else:
        passed.append("coop")

    # Information disclosure
    server = h.get("server", "")
    if re.search(r"\d+\.\d+|/\d", server):
        add("server_version", "Server", "Server header discloses a version", "low",
            f"Value is '{server[:80]}'.", "Remove version numbers from the Server header.")
    if "x-powered-by" in h:
        add("powered_by", "X-Powered-By", "X-Powered-By header reveals the technology stack", "low",
            f"Value is '{h['x-powered-by'][:80]}'.", "Remove the X-Powered-By header.")

    # Cookies
    cookie = h.get("set-cookie")
    if cookie:
        low = cookie.lower()
        missing = [f for f, ok in (("Secure", "secure" in low), ("HttpOnly", "httponly" in low), ("SameSite", "samesite" in low)) if not ok]
        if missing:
            add("cookie_flags", "Set-Cookie", "Cookie is missing security flags", "medium",
                "Missing: " + ", ".join(missing) + ".", "Set Secure, HttpOnly and SameSite on session cookies.")
        else:
            passed.append("cookie_flags")

    # CORS
    acao = h.get("access-control-allow-origin")
    if acao == "*":
        if h.get("access-control-allow-credentials", "").lower() == "true":
            add("cors", "Access-Control-Allow-Origin", "Wildcard CORS origin combined with credentials", "high",
                "Any site may be allowed to read authenticated responses.",
                "Return a specific allowed origin instead of '*' when credentials are allowed.")
        else:
            add("cors", "Access-Control-Allow-Origin", "CORS allows any origin", "info",
                "Fine for public data, risky for anything private.", "Restrict allowed origins if the API is not public.")

    by_severity = {s: 0 for s in PENALTY}
    for f in findings:
        by_severity[f["severity"]] += 1
    score = max(0, 100 - sum(PENALTY[f["severity"]] for f in findings))
    return {
        "summary": {
            "score": score,
            "grade": _grade(score),
            "total_findings": len(findings),
            "by_severity": by_severity,
        },
        "findings": findings,
        "passed_checks": passed,
    }

# ============================ SECTION: schemas ============================= #
Severity = Literal["critical", "high", "medium", "low", "info"]
CheckName = Literal["secrets", "pii"]


# ----------------------------- /v1/scan ----------------------------------- #
class ScanRequest(BaseModel):
    model_config = ConfigDict(
        extra="forbid",  # unknown fields are rejected, so typos do not silently pass
        json_schema_extra={
            "example": {
                "content": "db_url = postgres://admin:Zx9fQ2mK8vLp3T@db.internal:5432/app\ncontact: jane.doe@example.com",
                "checks": ["secrets", "pii"],
                "max_findings": 100,
            }
        },
    )

    content: str = Field(
        ...,
        min_length=1,
        max_length=MAX_CONTENT_CHARS,
        description="Text, source code, config file or log output to scan.",
    )
    checks: list[CheckName] = Field(
        default_factory=lambda: ["secrets", "pii"],
        min_length=1,
        max_length=2,
        description="Which detectors to run: 'secrets' (API keys, tokens, private keys) and/or 'pii' (cards, SSNs, IBANs, emails).",
    )
    max_findings: int = Field(default=100, ge=1, le=500, description="Maximum findings returned (counts in the summary are always complete).")

    @field_validator("content")
    @classmethod
    def content_not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("content must not be blank")
        return v

    @field_validator("checks")
    @classmethod
    def unique_checks(cls, v: list[str]) -> list[str]:
        return list(dict.fromkeys(v))


class Finding(BaseModel):
    id: str
    rule: str = Field(description="Stable rule identifier, see GET /v1/rules.")
    category: CheckName
    title: str
    severity: Severity
    line: int = Field(description="1-based line number.")
    column: int = Field(description="1-based column number.")
    match_preview: str = Field(description="Masked value. The full secret or personal data is never returned.")
    fingerprint: Optional[str] = Field(default=None, description="Short one-way hash of a secret, for de-duplication (secrets only).")
    recommendation: str


class ScanSummary(BaseModel):
    risk_score: int = Field(ge=0, le=100)
    risk_level: Literal["none", "low", "medium", "high", "critical"]
    total_findings: int
    returned_findings: int
    truncated: bool
    by_severity: dict[str, int]
    by_category: dict[str, int]


class ScanMeta(BaseModel):
    engine_version: str
    checks: list[CheckName]
    chars_scanned: int
    lines_scanned: int
    duration_ms: float


class ScanResponse(BaseModel):
    request_id: str
    summary: ScanSummary
    findings: list[Finding]
    meta: ScanMeta


# -------------------------- /v1/headers/analyze --------------------------- #
class HeadersRequest(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {
                "headers": {
                    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                    "X-Content-Type-Options": "nosniff",
                    "Server": "nginx/1.18.0",
                }
            }
        },
    )

    headers: dict[str, str] = Field(
        ...,
        min_length=1,
        max_length=100,
        description="HTTP response headers of the site you want to check, as name/value pairs.",
    )

    @field_validator("headers")
    @classmethod
    def header_sizes(cls, v: dict[str, str]) -> dict[str, str]:
        for name, value in v.items():
            if not name.strip() or len(name) > 100:
                raise ValueError("header names must be 1 to 100 characters")
            if len(value) > 4096:
                raise ValueError(f"value of header '{name[:50]}' exceeds 4096 characters")
        return v


class HeaderFinding(BaseModel):
    id: str
    check: str
    header: Optional[str]
    title: str
    severity: Severity
    detail: str
    recommendation: str


class HeadersSummary(BaseModel):
    score: int = Field(ge=0, le=100)
    grade: Literal["A", "B", "C", "D", "F"]
    total_findings: int
    by_severity: dict[str, int]


class HeadersResponse(BaseModel):
    request_id: str
    summary: HeadersSummary
    findings: list[HeaderFinding]
    passed_checks: list[str]


# ------------------------------- misc ------------------------------------- #
class RuleInfo(BaseModel):
    id: str
    category: CheckName
    severity: Severity
    title: str


class RulesResponse(BaseModel):
    request_id: str
    engine_version: str
    rules: list[RuleInfo]


class ErrorDetail(BaseModel):
    field: str
    message: str
    type: str


class ErrorBody(BaseModel):
    code: str
    message: str
    request_id: Optional[str] = None
    details: Optional[list[ErrorDetail]] = None


class ErrorResponse(BaseModel):
    error: ErrorBody


# ============================ SECTION: routes ============================== #
def verify_proxy_secret(request: Request) -> None:
    """Reject any request that did not come through the RapidAPI gateway.

    Read straight from the request (not declared as a parameter) so it does not
    show up as an input field in your API docs.
    """
    if not RAPIDAPI_PROXY_SECRET:
        return  # local development only; production startup requires a secret
    supplied = request.headers.get("x-rapidapi-proxy-secret", "")
    # compare_digest avoids leaking information through response timing
    if not hmac.compare_digest(supplied.encode("utf-8"), RAPIDAPI_PROXY_SECRET.encode("utf-8")):
        raise HTTPException(status_code=401, detail="Missing or invalid gateway credentials")


# Every route under /v1 requires the RapidAPI proxy secret.
router = APIRouter(prefix="/v1", dependencies=[Depends(verify_proxy_secret)])

_ERRORS = {
    401: {"model": ErrorResponse, "description": "Missing or invalid gateway credentials"},
    413: {"model": ErrorResponse, "description": "Request body too large"},
    422: {"model": ErrorResponse, "description": "Validation error"},
    429: {"model": ErrorResponse, "description": "Rate limit exceeded (enforced by the RapidAPI gateway)"},
    500: {"model": ErrorResponse, "description": "Unexpected server error"},
}


# These handlers are plain `def` (not `async def`) on purpose: scanning is CPU-bound, so FastAPI
# runs them in a worker thread and the event loop stays free to serve other requests.
@router.post(
    "/scan",
    response_model=ScanResponse,
    operation_id="scanContent",
    summary="Scan text or code for leaked secrets and personal data",
    description=(
        "Detects API keys, tokens, private keys and credentials in URLs (`secrets`), and payment card numbers, "
        "US SSNs, IBANs and email addresses (`pii`). Matched values are masked in the response and the "
        "submitted content is never stored or logged."
    ),
    tags=["Scanning"],
    responses=_ERRORS,
)
def scan(payload: ScanRequest, request: Request) -> ScanResponse:
    started = time.perf_counter()
    result = scan_content(payload.content, payload.checks, payload.max_findings)
    return ScanResponse(
        request_id=request.state.request_id,
        summary=result.summary,
        findings=result.findings,
        meta=ScanMeta(
            engine_version=ENGINE_VERSION,
            checks=payload.checks,
            chars_scanned=result.chars,
            lines_scanned=result.lines,
            duration_ms=round((time.perf_counter() - started) * 1000, 2),
        ),
    )


@router.post(
    "/headers/analyze",
    response_model=HeadersResponse,
    operation_id="analyzeHeaders",
    summary="Grade the security of a site's HTTP response headers",
    description=(
        "Send the response headers of your site and get a score, a grade (A to F) and specific fixes. "
        "The service only analyzes the headers you submit; it never contacts your site."
    ),
    tags=["Scanning"],
    responses=_ERRORS,
)
def analyze(payload: HeadersRequest, request: Request) -> HeadersResponse:
    result = analyze_headers(payload.headers)
    return HeadersResponse(request_id=request.state.request_id, **result)


@router.get(
    "/rules",
    response_model=RulesResponse,
    operation_id="listRules",
    summary="List the detection rules",
    tags=["Reference"],
    responses={k: v for k, v in _ERRORS.items() if k in (401, 500)},
)
def rules(request: Request) -> RulesResponse:
    return RulesResponse(
        request_id=request.state.request_id,
        engine_version=ENGINE_VERSION,
        rules=[RuleInfo(id=r.id, category=r.category, severity=r.severity, title=r.title) for r in RULES],
    )


# ============================ SECTION: app ================================= #
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9_\-]{8,64}$")
_ERROR_CODES = {
    400: "bad_request", 401: "unauthorized", 403: "forbidden", 404: "not_found",
    405: "method_not_allowed", 413: "payload_too_large", 415: "unsupported_media_type",
    422: "validation_error", 429: "rate_limited",
}


@asynccontextmanager
async def lifespan(_: FastAPI):
    # Fail fast: a production API with no gateway secret would let anyone call it directly
    # and bypass RapidAPI billing and rate limits.
    if ENVIRONMENT == "production" and not RAPIDAPI_PROXY_SECRET:
        raise RuntimeError("RAPIDAPI_PROXY_SECRET must be set when ENVIRONMENT=production")
    if not RAPIDAPI_PROXY_SECRET:
        log.warning("RAPIDAPI_PROXY_SECRET is empty: the API is open to direct calls (development mode)")
    log.info("SentinelAI API %s started (environment=%s)", VERSION, ENVIRONMENT)
    yield


app = FastAPI(
    title="SentinelAI API",
    version=VERSION,
    description=(
        "Security micro-API for developers and security teams.\n\n"
        "* **Secrets and PII scanner**: find leaked API keys, tokens, private keys, payment card numbers, "
        "SSNs, IBANs and emails in text or code.\n"
        "* **Header analyzer**: grade a site's HTTP security headers.\n\n"
        "Submitted content is processed in memory only and is never stored or logged."
    ),
    lifespan=lifespan,
    docs_url="/docs" if ENABLE_DOCS else None,
    redoc_url="/redoc" if ENABLE_DOCS else None,
    openapi_url="/openapi.json",
)
app.include_router(router)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def error_response(status: int, code: str, message: str, request: Optional[Request] = None, details: Optional[list] = None) -> JSONResponse:
    """Every error leaves the API in the same JSON shape."""
    request_id = getattr(request.state, "request_id", None) if request is not None else None
    body = {"error": {"code": code, "message": message, "request_id": request_id}}
    if details:
        body["error"]["details"] = details
    return JSONResponse(status_code=status, content=body)


@app.exception_handler(StarletteHTTPException)
async def http_error_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    message = exc.detail if isinstance(exc.detail, str) else "Request failed"
    return error_response(exc.status_code, _ERROR_CODES.get(exc.status_code, "http_error"), message, request)


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    # Only the field path, message and type are returned. Submitted values are left out on purpose,
    # so secrets or personal data in a bad request are never echoed back or logged.
    details = [
        {"field": ".".join(str(p) for p in e["loc"][1:]) or "body", "message": e["msg"], "type": e["type"]}
        for e in exc.errors()
    ]
    return error_response(422, "validation_error", "Request validation failed", request, details)


@app.exception_handler(Exception)
async def unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
    log.exception("Unhandled error on %s %s", request.method, request.url.path)
    return error_response(500, "internal_error", "An unexpected error occurred", request)


@app.middleware("http")
async def request_context(request: Request, call_next):
    """Adds a request ID, enforces the body size limit and writes one access-log line per request."""
    supplied = request.headers.get("x-request-id", "")
    request.state.request_id = supplied if _REQUEST_ID_RE.match(supplied) else uuid.uuid4().hex
    started = time.perf_counter()

    length = request.headers.get("content-length", "")
    if length.isdigit() and int(length) > MAX_BODY_BYTES:
        response = error_response(413, "payload_too_large", "Request body is too large", request)
    else:
        try:
            response = await call_next(request)
        except Exception:  # last line of defense; the handler above covers most cases
            log.exception("Unhandled error on %s %s", request.method, request.url.path)
            response = error_response(500, "internal_error", "An unexpected error occurred", request)

    response.headers["X-Request-ID"] = request.state.request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store"
    # Log metadata only: never the body, headers or query string.
    log.info(
        "request_id=%s method=%s path=%s status=%s duration_ms=%.1f",
        request.state.request_id, request.method, request.url.path, response.status_code,
        (time.perf_counter() - started) * 1000,
    )
    return response


@app.get("/health", include_in_schema=False)
def health() -> dict:
    """Render health check. Not part of the public RapidAPI listing."""
    return {"status": "ok", "version": VERSION}
