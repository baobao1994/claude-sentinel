#!/usr/bin/env python3
"""Generate bundled region data from Anthropic's public supported-countries page.

Dev-only helper. Runtime parsing lives in collectors/official.py and uses the
generated alias table, so the tool still works offline.
"""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pycountry
from bs4 import BeautifulSoup

URL = "https://www.anthropic.com/supported-countries"
OUT = Path(__file__).resolve().parents[1] / "src" / "claude_sentinel" / "data"

ALIASES = {
    "Türkiye (Turkey)": "TR",
    "Turkey": "TR",
    "Côte d'Ivoire": "CI",
    "Congo, Democratic Republic of (DRC)": "CD",
    "Congo (Brazzaville)": "CG",
    "Congo, Republic of the": "CG",
    "Vatican City": "VA",
    "Holy See (Vatican City)": "VA",
    "Palestine": "PS",
    "Timor-Leste": "TL",
    "Timor-Leste, Democratic Republic of": "TL",
    "South Korea": "KR",
    "United States of America": "US",
    "Taiwan": "TW",
    "Laos": "LA",
    "Moldova": "MD",
    "Bolivia": "BO",
    "Venezuela": "VE",
    "Iran": "IR",
    "Syria": "SY",
    "North Korea": "KP",
    "Russia": "RU",
    "Micronesia": "FM",
    "Czechia (Czech Republic)": "CZ",
    "North Macedonia": "MK",
    "Bosnia and Herzegovina": "BA",
    "Cabo Verde": "CV",
    "Eswatini": "SZ",
    "São Tomé and Príncipe": "ST",
    "Sao Tome and Principe": "ST",
}


def norm(name: str) -> str:
    return (
        name.replace("’", "'")
        .replace("‘", "'")
        .strip()
        .lower()
    )


def iso_for(name: str) -> str | None:
    if name in ALIASES:
        return ALIASES[name]
    cleaned = re.sub(r"\s*\(.*?\)\s*", "", name).strip()
    if cleaned in ALIASES:
        return ALIASES[cleaned]
    for candidate in (name, cleaned):
        try:
            return pycountry.countries.lookup(candidate).alpha_2
        except LookupError:
            pass
    try:
        results = pycountry.countries.search_fuzzy(cleaned)
        if results:
            return results[0].alpha_2
    except LookupError:
        pass
    return None


def main() -> int:
    with httpx.Client(timeout=20, follow_redirects=True, headers={"User-Agent": "Mozilla/5.0"}) as c:
        resp = c.get(URL)
    resp.raise_for_status()
    soup = BeautifulSoup(resp.text, "html.parser")

    uls = soup.find_all("ul")
    if not uls:
        print("no list found", file=sys.stderr)
        return 1
    # The policy page also contains navigation and "Use by ..." lists.
    # The country list is by far the largest one.
    ul = max(uls, key=lambda u: len(u.find_all("li")))
    if len(ul.find_all("li")) < 50:
        print("country list too small", file=sys.stderr)
        return 1

    names = []
    for li in ul.find_all("li"):
        text = li.get_text(" ", strip=True)
        if not text or len(text) > 80 or "Use by" in text:
            continue
        names.append(text)
    names = list(dict.fromkeys(names))

    countries = []
    by_name = {}
    unknown = []
    for name in names:
        code = iso_for(name)
        if not code:
            unknown.append(name)
            continue
        by_name[name] = code
        by_name.setdefault(norm(name), code)
        countries.append({"code": code, "name": name})

    dedup = {}
    for item in countries:
        dedup.setdefault(item["code"], item)
    countries = sorted(dedup.values(), key=lambda x: x["name"])

    effective = None
    m = re.search(r"Effective\s+([A-Z][a-z]+ \d{1,2}, \d{4})", soup.get_text(" ", strip=True))
    if m:
        effective = m.group(1)

    OUT.mkdir(parents=True, exist_ok=True)
    regions = {
        "effective": effective,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "source_url": URL,
        "scope": "all",
        "countries": countries,
    }
    (OUT / "regions.json").write_text(json.dumps(regions, ensure_ascii=False, indent=2), encoding="utf-8")

    aliases = {
        "source_url": URL,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "by_name": by_name,
        "by_code": {c["code"]: c["name"] for c in countries},
    }
    (OUT / "region_aliases.json").write_text(json.dumps(aliases, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"countries={len(countries)} unknown={len(unknown)} effective={effective}")
    if unknown:
        print("unknown:", unknown)
    for code in ("CN", "HK", "MO", "TW", "RU", "US", "SG", "JP"):
        print(code, "in" if code in dedup else "OUT")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
