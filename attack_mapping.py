import json
import os
import re

ATTACK_INDEX_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mitre_attack", "enterprise_techniques.json")
APPLICABLE_PLATFORMS = {"Linux", "Containers", "ESXi"}
MAX_REVOCATION_HOPS = 5

_ATTACK_LINE_RE = re.compile(r"^[\s*_#]*ATT(?:&|A)?CK[\s*_]*:(.*)$", re.IGNORECASE | re.MULTILINE)
_TECHNIQUE_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

_index = None


def load_attack_index():
    global _index
    if _index is None:
        try:
            with open(ATTACK_INDEX_PATH, encoding="utf-8") as f:
                _index = json.load(f)
        except (OSError, ValueError):
            return {}
    return _index


def extract_attack_ids(text):
    lines = _ATTACK_LINE_RE.findall(text or "")
    ids = []
    for line in lines:
        for tid in _TECHNIQUE_ID_RE.findall(line.upper()):
            if tid not in ids:
                ids.append(tid)
    return ids


def _resolve(tid, techniques):
    current = tid
    for _ in range(MAX_REVOCATION_HOPS):
        entry = techniques.get(current)
        if entry is None or "revoked_by" not in entry:
            return current, entry
        if not entry["revoked_by"]:
            return current, None
        current = entry["revoked_by"]
    return current, None


def validate_attack_ids(ids):
    index = load_attack_index()
    if not index:
        return None
    techniques = index["techniques"]
    tactic_names = index["tactics"]
    version = index.get("version", "?")
    accepted, rejected, seen = [], [], set()
    for tid in ids:
        original = techniques.get(tid)
        if original is None:
            rejected.append({"id": tid, "reason": f"unknown ID in ATT&CK v{version}"})
            continue
        resolved_id, entry = _resolve(tid, techniques)
        if entry is None:
            rejected.append({"id": tid, "reason": "revoked with no replacement"})
            continue
        if entry.get("deprecated"):
            rejected.append({"id": tid, "reason": "deprecated"})
            continue
        if not APPLICABLE_PLATFORMS.intersection(entry.get("platforms", [])):
            rejected.append({"id": tid, "reason": f"not applicable to Linux/ESXi ({', '.join(entry.get('platforms', [])) or 'no platform'})"})
            continue
        if resolved_id in seen:
            continue
        seen.add(resolved_id)
        accepted.append({
            "id": resolved_id,
            "name": entry["name"],
            "tactics": [tactic_names.get(t, t) for t in entry.get("tactics", [])],
            "url": entry.get("url", ""),
            "replaces": tid if resolved_id != tid else None,
        })
    return {"version": version, "techniques": accepted, "rejected": rejected}


def map_attack(analysis_text):
    return validate_attack_ids(extract_attack_ids(analysis_text))

