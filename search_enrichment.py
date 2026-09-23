import ipaddress
import json
import re
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

QUERY_TEMPLATES = {
    "ip": "{} malicious activity threat intelligence",
    "hash": "{} malware hash analysis",
    "domain": "{} malicious domain threat intelligence",
}

SEARCH_DECISION_PROMPT = """### Instruction:
The indicators below were extracted from a security event batch. Decide which of them, if any, are worth an external internet search to check for prior-known malicious activity (e.g. a public IP already reported as a scanner or C2 host, a file hash already flagged as malware, a domain that looks like attacker infrastructure). Do not select an indicator that is clearly benign, generic, or unlikely to return useful results (e.g. a well-known public DNS resolver, a package-manager or library domain, a filename fragment misread as a domain).

Indicators found:
{candidates_block}

Batch context (for reference only):
{log_content}

Output one line per indicator worth searching, in this exact format:
SEARCH: <indicator>
If none are worth searching, output exactly:
SEARCH: NONE

### Response:
"""


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


class SearchProvider:
    def search(self, query, max_results=MAX_RESULTS_PER_TERM):
        raise NotImplementedError


class TavilyProvider(SearchProvider):
    def __init__(self, api_key):
        self.api_key = api_key

    def search(self, query, max_results=MAX_RESULTS_PER_TERM):
        data = {
            "api_key": self.api_key,
            "query": query,
            "search_depth": "basic",
            "max_results": max_results,
        }
        req = urllib.request.Request(
            "https://api.tavily.com/search",
            data=json.dumps(data).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        return [
            {"title": r.get("title", ""), "url": r.get("url", ""), "snippet": r.get("content", "")}
            for r in payload.get("results", [])
        ]


_PROVIDERS = {"tavily": TavilyProvider}


def get_search_provider(name, api_key):
    if not api_key:
        return None
    provider_cls = _PROVIDERS.get(name)
    if not provider_cls:
        return None
    return provider_cls(api_key)


def _flat_candidates(candidates):
    return [(kind, value) for kind, values in candidates.items() for value in values]


def run_decision(llm_sync_fn, batch_data, candidates):
    flat = _flat_candidates(candidates)
    if not flat:
        return []
    candidates_block = "\n".join(f"- {kind}: {value}" for kind, value in flat)
    prompt = SEARCH_DECISION_PROMPT.format(candidates_block=candidates_block, log_content=batch_data[-4000:])
    raw = llm_sync_fn(prompt)
    if not raw:
        return []
    valid_values = {value for _, value in flat}
    accepted = []
    for line in raw.splitlines():
        line = line.strip()
        if not line.upper().startswith("SEARCH:"):
            continue
        value = line.split(":", 1)[1].strip()
        if value.upper() == "NONE":
            continue
        if value in valid_values and value not in accepted:
            accepted.append(value)
        if len(accepted) >= MAX_AUTO_SEARCH_TERMS:
            break
    return accepted


def select_manual_terms(candidates):
    flat = [value for values in candidates.values() for value in values]
    return flat[:MAX_MANUAL_SEARCH_TERMS]


def search_terms(provider, terms, candidates):
    term_kind = {value: kind for kind, values in candidates.items() for value in values}
    sources = []
    for term in terms:
        kind = term_kind.get(term, "domain")
        query = QUERY_TEMPLATES[kind].format(term)
        try:
            results = provider.search(query, max_results=MAX_RESULTS_PER_TERM)
        except Exception as e:
            sources.append({"term": term, "type": kind, "title": "Search failed", "url": "", "snippet": str(e)[:200]})
            continue
        for r in results[:MAX_RESULTS_PER_TERM]:
            sources.append({
                "term": term,
                "type": kind,
                "title": (r.get("title") or "")[:200],
                "url": r.get("url") or "",
                "snippet": (r.get("snippet") or "")[:SNIPPET_MAX_CHARS],
            })
    return sources


def enrich_automatic(batch_data, llm_sync_fn, provider):
    candidates = extract_search_candidates(batch_data)
    if not any(candidates.values()):
        return {"performed": False, "terms": [], "sources": [], "note": "No public indicators found in this batch."}
    if provider is None:
        return {"performed": False, "terms": [], "sources": [], "note": "Search provider not configured."}
    terms = run_decision(llm_sync_fn, batch_data, candidates)
    if not terms:
        return {"performed": False, "terms": [], "sources": [], "note": "No indicators were judged worth an external search."}
    sources = search_terms(provider, terms, candidates)
    return {"performed": True, "terms": terms, "sources": sources, "note": None}


def enrich_manual(batch_data, provider):
    candidates = extract_search_candidates(batch_data)
    if not any(candidates.values()):
        return {"performed": False, "terms": [], "sources": [], "note": "No public indicators found in this batch."}
    if provider is None:
        return {"performed": False, "terms": [], "sources": [], "note": "Search provider not configured."}
    terms = select_manual_terms(candidates)
    sources = search_terms(provider, terms, candidates)
    return {"performed": True, "terms": terms, "sources": sources, "note": None}


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
