import ipaddress
import json
import re
import threading
import time
import urllib.error
import urllib.request

MAX_AUTO_SEARCH_TERMS = 3
MAX_MANUAL_SEARCH_TERMS = 5
MAX_RESULTS_PER_TERM = 3
SNIPPET_MAX_CHARS = 300

NO_SEARCH_TEXT = "No external search was performed for this batch."

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HASH_RE = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")
_DOMAIN_TLD_BLOCKLIST = {
    "py", "so", "sh", "bt", "md", "js", "json", "log", "txt", "pid", "list",
    "yml", "yaml", "conf", "service", "desktop", "c", "h", "o", "cfg", "ini",
    "html", "css", "pyc", "bak", "tar", "gz", "zip", "csv", "pl", "rb",
}
_DOMAIN_RE = re.compile(r"(?<![\w./])(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+([a-zA-Z]{2,24})\b")

def _is_public_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_reserved or addr.is_multicast or addr.is_unspecified)


def extract_search_candidates(text):
    ips = sorted({ip for ip in _IP_RE.findall(text) if _is_public_ip(ip)})
    hashes = sorted(set(_HASH_RE.findall(text)))
    domains = sorted({
        m.group(0) for m in _DOMAIN_RE.finditer(text)
        if m.group(1).lower() not in _DOMAIN_TLD_BLOCKLIST
    })
    return {"ip": ips, "hash": hashes, "domain": domains}


VT_SUSPICIOUS_MIN = 3
VT_MALICIOUS_MIN = 10
ABUSEIPDB_SUSPICIOUS_MIN = 25
ABUSEIPDB_MALICIOUS_MIN = 75


def assess_virustotal(malicious):
    if malicious == 0:
        return "clean"
    if malicious < VT_SUSPICIOUS_MIN:
        return "negligible (likely false positive)"
    if malicious < VT_MALICIOUS_MIN:
        return "suspicious"
    return "malicious"


def assess_abuseipdb(score, reports):
    if reports == 0 or score < ABUSEIPDB_SUSPICIOUS_MIN:
        return "clean"
    if score < ABUSEIPDB_MALICIOUS_MIN:
        return "suspicious"
    return "malicious"


class ReputationProvider:
    def check(self, indicator, kind):
        raise NotImplementedError


class AbuseIPDBProvider(ReputationProvider):
    def __init__(self, api_key):
        self.api_key = api_key

    def check(self, indicator, kind):
        req = urllib.request.Request(
            f"https://api.abuseipdb.com/api/v2/check?ipAddress={indicator}&maxAgeInDays=180",
            headers={"Key": self.api_key, "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        data = payload.get("data", {})
        score = data.get("abuseConfidenceScore", 0)
        reports = data.get("totalReports", 0)
        assessment = assess_abuseipdb(score, reports)
        if reports == 0:
            title = f"AbuseIPDB assessment: {assessment} — no abuse reports found for {indicator}"
        else:
            title = f"AbuseIPDB assessment: {assessment} — {score}% abuse confidence, {reports} report(s) in the last 180 days"
        snippet = (
            f"ISP: {data.get('isp') or '?'} · Country: {data.get('countryCode') or '?'} · "
            f"Usage: {data.get('usageType') or '?'} · Last reported: {data.get('lastReportedAt') or 'never'}"
        )
        return [{"title": title, "url": f"https://www.abuseipdb.com/check/{indicator}", "snippet": snippet}]


class VirusTotalProvider(ReputationProvider):
    _API_PATHS = {"hash": "files", "domain": "domains", "ip": "ip_addresses"}
    _GUI_PATHS = {"hash": "file", "domain": "domain", "ip": "ip-address"}
    _LABELS = {"hash": "hash", "domain": "domain", "ip": "IP"}

    def __init__(self, api_key):
        self.api_key = api_key

    def check(self, indicator, kind):
        gui_url = f"https://www.virustotal.com/gui/{self._GUI_PATHS[kind]}/{indicator}"
        label = self._LABELS[kind]
        req = urllib.request.Request(
            f"https://www.virustotal.com/api/v3/{self._API_PATHS[kind]}/{indicator}",
            headers={"x-apikey": self.api_key},
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return [{
                    "title": f"VirusTotal assessment: unknown — {label} {indicator} has no prior record",
                    "url": gui_url,
                    "snippet": f"This exact {label} was never seen by VirusTotal.",
                }]
            raise
        attrs = payload.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 0
        assessment = assess_virustotal(malicious)
        title = (
            f"VirusTotal assessment: {assessment} — "
            f"{malicious}/{total} engines flagged this {label} as malicious ({suspicious} suspicious)"
        )
        if kind == "hash":
            names = attrs.get("names") or ([attrs["meaningful_name"]] if attrs.get("meaningful_name") else [])
            label_hint = (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label")
            snippet = (
                f"Type: {attrs.get('type_description') or '?'} · Known as: {', '.join(names[:3]) or 'n/a'} · "
                f"Threat label: {label_hint or 'n/a'}"
            )
        elif kind == "ip":
            snippet = (
                f"AS owner: {attrs.get('as_owner') or '?'} · Country: {attrs.get('country') or '?'} · "
                f"Community reputation: {attrs.get('reputation', 0)}"
            )
        else:
            categories = sorted(set((attrs.get("categories") or {}).values()))
            snippet = (
                f"Registrar: {attrs.get('registrar') or '?'} · Categories: {', '.join(categories[:3]) or 'n/a'} · "
                f"Community reputation: {attrs.get('reputation', 0)}"
            )
        return [{"title": title, "url": gui_url, "snippet": snippet}]


def get_reputation_providers(abuseipdb_api_key, virustotal_api_key):
    providers = {"ip": [], "hash": [], "domain": []}
    if abuseipdb_api_key:
        providers["ip"].append(AbuseIPDBProvider(abuseipdb_api_key))
    if virustotal_api_key:
        vt = VirusTotalProvider(virustotal_api_key)
        for kind in ("ip", "hash", "domain"):
            providers[kind].append(vt)
    return {kind: lst for kind, lst in providers.items() if lst}


CACHE_TTL_SECONDS = 6 * 3600

_cache = {}
_cache_lock = threading.Lock()


def _cached_lookup(source, indicator, fetch_fn):
    key = (source, indicator)
    now = time.time()
    with _cache_lock:
        hit = _cache.get(key)
        if hit and hit[0] > now:
            return hit[1]
    results = fetch_fn()
    with _cache_lock:
        _cache[key] = (now + CACHE_TTL_SECONDS, results)
    return results


def clear_lookup_cache():
    with _cache_lock:
        _cache.clear()


_BENIGN_IP_NETWORKS = [ipaddress.ip_network(n) for n in (
    "8.8.8.8/32", "8.8.4.4/32",
    "1.1.1.1/32", "1.0.0.1/32",
    "9.9.9.9/32", "149.112.112.112/32",
    "208.67.222.222/32", "208.67.220.220/32",
    "91.189.88.0/21", "185.125.188.0/22",
)]

_BENIGN_DOMAIN_SUFFIXES = (
    "ubuntu.com", "canonical.com", "launchpad.net", "snapcraft.io",
    "debian.org", "kernel.org", "python.org", "pypi.org", "pythonhosted.org",
    "github.com", "githubusercontent.com", "docker.io", "docker.com",
    "npmjs.org", "npmjs.com", "google.com", "googleapis.com", "gstatic.com",
    "cloudflare.com", "microsoft.com", "mozilla.org",
)


def is_known_benign(kind, value):
    if kind == "ip":
        addr = ipaddress.ip_address(value)
        return any(addr in net for net in _BENIGN_IP_NETWORKS)
    if kind == "domain":
        v = value.lower()
        return any(v == d or v.endswith("." + d) for d in _BENIGN_DOMAIN_SUFFIXES)
    return False


def _flat_candidates(candidates):
    return [(kind, value) for kind, values in candidates.items() for value in values]


def select_automatic_terms(candidates):
    return [
        value for kind, value in _flat_candidates(candidates)
        if not is_known_benign(kind, value)
    ][:MAX_AUTO_SEARCH_TERMS]


def select_manual_terms(candidates):
    return [value for _, value in _flat_candidates(candidates)][:MAX_MANUAL_SEARCH_TERMS]


def _lookup(term, kind, reputation_providers):
    reps = reputation_providers.get(kind) or []
    if not reps:
        return None
    results = []
    for rep in reps:
        results.extend(_cached_lookup(type(rep).__name__, term, lambda rep=rep: rep.check(term, kind))[:MAX_RESULTS_PER_TERM])
    return results


def search_terms(terms, candidates, reputation_providers=None):
    reputation_providers = reputation_providers or {}
    term_kind = {value: kind for kind, values in candidates.items() for value in values}
    sources = []
    for term in terms:
        kind = term_kind.get(term, "domain")
        try:
            results = _lookup(term, kind, reputation_providers)
        except Exception as e:
            sources.append({"term": term, "type": kind, "title": "Lookup failed", "url": "", "snippet": str(e)[:200]})
            continue
        if results is None:
            sources.append({"term": term, "type": kind, "title": "No provider configured for this indicator type", "url": "", "snippet": ""})
            continue
        for r in results:
            sources.append({
                "term": term,
                "type": kind,
                "title": (r.get("title") or "")[:200],
                "url": r.get("url") or "",
                "snippet": (r.get("snippet") or "")[:SNIPPET_MAX_CHARS],
            })
    return sources


def _enrich(batch_data, reputation_providers, select_fn, empty_note):
    reputation_providers = reputation_providers or {}
    candidates = extract_search_candidates(batch_data)
    if not any(candidates.values()):
        return {"performed": False, "terms": [], "sources": [], "note": "No public indicators found in this batch."}
    if not reputation_providers:
        return {"performed": False, "terms": [], "sources": [], "note": "No reputation provider configured."}
    terms = select_fn(candidates)
    if not terms:
        return {"performed": False, "terms": [], "sources": [], "note": empty_note}
    sources = search_terms(terms, candidates, reputation_providers)
    return {"performed": True, "terms": terms, "sources": sources, "note": None}


def enrich_automatic(batch_data, reputation_providers=None):
    return _enrich(batch_data, reputation_providers, select_automatic_terms,
                   "All indicators in this batch belong to known benign infrastructure.")


def enrich_manual(batch_data, reputation_providers=None):
    return _enrich(batch_data, reputation_providers, select_manual_terms,
                   "No public indicators found in this batch.")


def format_search_block(result):
    if not result or not result.get("performed"):
        note = (result or {}).get("note")
        return note or NO_SEARCH_TEXT
    lines = []
    for term in result["terms"]:
        term_sources = [s for s in result["sources"] if s["term"] == term]
        lines.append(f"Indicator: {term}")
        if not term_sources:
            lines.append("  No relevant results found.")
        for i, s in enumerate(term_sources, 1):
            lines.append(f"  {i}. {s['title']} — {s['snippet']} ({s['url']})")
    return "\n".join(lines)
