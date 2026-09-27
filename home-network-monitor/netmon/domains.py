"""Domain-name helpers: normalisation, registrable-domain guess, entropy."""

from __future__ import annotations

import math
import re
from collections import Counter

# Common multi-label public suffixes. Not a full Public Suffix List, but good
# enough to group "foo.bbc.co.uk" under "bbc.co.uk" for reporting.
_MULTI_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "org.nz", "co.jp", "ne.jp", "or.jp", "co.kr", "co.in", "net.in",
    "org.in", "firm.in", "gen.in", "ind.in", "com.br", "com.mx", "com.cn",
    "com.hk", "com.sg", "com.tw", "com.tr", "co.za", "com.ar",
    "cloudfront.net", "amazonaws.com", "azurewebsites.net", "blob.core.windows.net",
    "herokuapp.com", "github.io", "appspot.com", "firebaseapp.com", "web.app",
    "pages.dev", "workers.dev", "netlify.app", "vercel.app", "duckdns.org",
    "ngrok.io", "ngrok-free.app", "trycloudflare.com",
}

_LABEL_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

# Local / infrastructure names that are never interesting as "internet hosts".
LOCAL_SUFFIXES = (".local", ".lan", ".home", ".arpa", ".localdomain", ".internal", ".attlocal.net")


def normalize(name: str) -> str | None:
    """Lower-case, strip trailing dot, validate. Returns None for garbage."""
    if not name:
        return None
    name = name.strip().rstrip(".").lower()
    if not name or len(name) > 253:
        return None
    if _IPV4_RE.match(name):
        return name
    labels = name.split(".")
    if any(not _LABEL_RE.match(label) for label in labels):
        return None
    return name


def is_local(name: str) -> bool:
    return "." not in name or name.endswith(LOCAL_SUFFIXES)


def base_domain(name: str) -> str:
    """Best-effort registrable domain ("eTLD+1")."""
    if _IPV4_RE.match(name):
        return name
    labels = name.split(".")
    if len(labels) <= 2:
        return name
    for take in (4, 3):
        if len(labels) > take:
            suffix = ".".join(labels[-(take - 1):])
            if suffix in _MULTI_SUFFIXES:
                return ".".join(labels[-take:])
    last_two = ".".join(labels[-2:])
    if last_two in _MULTI_SUFFIXES:
        return ".".join(labels[-3:])
    return last_two


def tld(name: str) -> str:
    return name.rsplit(".", 1)[-1]


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def dga_score(name: str, entropy_threshold: float = 3.6) -> tuple[bool, str]:
    """Heuristic check for algorithmically generated domain names.

    Only the registrable label is scored (e.g. ``xk2j9qpl4mzt`` in
    ``xk2j9qpl4mzt.com``), because CDNs routinely use random-looking
    sub-domains under well-known parents.
    """
    base = base_domain(name)
    if _IPV4_RE.match(base):
        return False, ""
    label = base.split(".")[0]
    if len(label) < 10:
        return False, ""
    entropy = shannon_entropy(label)
    vowels = sum(ch in "aeiou" for ch in label)
    digits = sum(ch.isdigit() for ch in label)
    vowel_ratio = vowels / len(label)
    digit_ratio = digits / len(label)
    consonant_run = max((len(m) for m in re.findall(r"[bcdfghjklmnpqrstvwxz]+", label)), default=0)

    score = 0
    if entropy >= entropy_threshold:
        score += 2
    if vowel_ratio < 0.2:
        score += 1
    if 0.15 <= digit_ratio <= 0.7:
        score += 1
    if consonant_run >= 6:
        score += 1
    if len(label) >= 16:
        score += 1
    suspicious = score >= 4
    reason = (
        f"label '{label}' entropy={entropy:.2f} vowels={vowel_ratio:.0%} "
        f"digits={digit_ratio:.0%} consonant_run={consonant_run}"
    )
    return suspicious, reason if suspicious else ""
