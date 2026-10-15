#!/usr/bin/env python3
import json
import os
import sys
import urllib.request

SOURCE_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
OUTPUT_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "mitre_attack", "enterprise_techniques.json")


def _external_id(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id"), ref.get("url")
    return None, None


def load_bundle(source):
    if os.path.exists(source):
        with open(source, encoding="utf-8") as f:
            return json.load(f)
    with urllib.request.urlopen(source, timeout=120) as resp:
        return json.loads(resp.read().decode("utf-8"))


def build_index(bundle):
    objects = bundle["objects"]
    by_stix_id = {o["id"]: o for o in objects}
    collection = next((o for o in objects if o["type"] == "x-mitre-collection"), {})
    tactics = {
        o["x_mitre_shortname"]: o["name"]
        for o in objects
        if o["type"] == "x-mitre-tactic" and not o.get("revoked") and not o.get("x_mitre_deprecated")
    }
    revoked_by = {
        r["source_ref"]: r["target_ref"]
        for r in objects
        if r["type"] == "relationship" and r.get("relationship_type") == "revoked-by"
    }
    techniques = {}
    for o in objects:
        if o["type"] != "attack-pattern":
            continue
        tid, url = _external_id(o)
        if not tid:
            continue
        entry = {
            "name": o.get("name", ""),
            "tactics": [k["phase_name"] for k in o.get("kill_chain_phases", []) if k.get("kill_chain_name") == "mitre-attack"],
            "platforms": o.get("x_mitre_platforms", []),
            "url": url,
        }
        if o.get("revoked"):
            target = by_stix_id.get(revoked_by.get(o["id"], ""))
            entry["revoked_by"] = _external_id(target)[0] if target else None
        if o.get("x_mitre_deprecated"):
            entry["deprecated"] = True
        techniques[tid] = entry
    return {
        "version": collection.get("x_mitre_version", "?"),
        "source": SOURCE_URL,
        "tactics": tactics,
        "techniques": dict(sorted(techniques.items())),
    }


def main():
    source = sys.argv[1] if len(sys.argv) > 1 else SOURCE_URL
    index = build_index(load_bundle(source))
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(index, f, indent=1, ensure_ascii=False)
    print(f"ATT&CK Enterprise v{index['version']}: {len(index['techniques'])} techniques, "
          f"{len(index['tactics'])} tactics -> {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
