#!/usr/bin/env python3
"""
Create or update a roadmap quarter page in Confluence by cloning the previous
quarter's page and transforming it (sprint dates, column highlights, Jira
fixVersion references, section labels, macro IDs).

Pages are expected to be titled by quarter ("YY.Q", e.g. "26.3") and to follow a
layout with deliverables tables headed "YY.Q Deliverables ( Completed ones are
stricken out )", sprint sub-labels like "YY.Q.1" ... "YY.Q.6", and Jira macros
that filter on fixVersion. Adjust transform_body() if your template differs.

Environment variables (or .env file):
  CONFLUENCE_BASE_URL        e.g. https://wiki.example.com
  CONFLUENCE_TOKEN           Personal access token (sent as a Bearer token)
  CONFLUENCE_SPACE_KEY       Space that holds the roadmap pages
  CONFLUENCE_PARENT_PAGE_ID  Parent page for new quarter pages (or --parent-id)

Usage:
    # Create 26.4 from 26.3 (source page auto-found by title)
    python3 create_roadmap_page.py --to 26.4

    # Create 27.1 from 26.4
    python3 create_roadmap_page.py --to 27.1

    # Preview transforms without publishing
    python3 create_roadmap_page.py --to 26.4 --dry-run

    # Override source page ID if auto-lookup fails
    python3 create_roadmap_page.py --to 26.4 --source-id 1234567

    # Override parent page ID
    python3 create_roadmap_page.py --to 27.1 --parent-id 9876543

    # Skip confirmation prompt
    python3 create_roadmap_page.py --to 26.4 --yes
"""

import argparse
import os
import re
import sys
import uuid
from calendar import monthrange
from typing import Optional

try:
    import requests
except ImportError:
    sys.exit("Missing dependency: pip install requests")

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

CONFLUENCE_BASE = os.environ.get("CONFLUENCE_BASE_URL", "").rstrip("/")
SPACE_KEY       = os.environ.get("CONFLUENCE_SPACE_KEY", "")
PARENT_PAGE_ID  = os.environ.get("CONFLUENCE_PARENT_PAGE_ID", "")

# Table highlight colours used in the deliverables table
COLOUR_CURRENT = "#b3d4ff"   # blue   — the quarter being delivered NOW
COLOUR_NEXT    = "#ffebe6"   # orange — the upcoming quarter


# ---------------------------------------------------------------------------
# Quarter version arithmetic
# ---------------------------------------------------------------------------

class Ver:
    """Represents a roadmap quarter like '26.3' (year=26, q=3)."""

    def __init__(self, s: str):
        try:
            parts = str(s).split(".")
            self.year, self.q = int(parts[0]), int(parts[1])
            if not (1 <= self.q <= 4):
                raise ValueError
        except (ValueError, IndexError):
            sys.exit(f"Error: invalid version '{s}'. Expected YY.Q format, e.g. 26.4 or 27.1")

    def __str__(self):
        return f"{self.year}.{self.q}"

    def __eq__(self, other):
        return str(self) == str(other)

    def __hash__(self):
        return hash(str(self))

    def next(self) -> "Ver":
        return Ver(f"{self.year}.{self.q + 1}") if self.q < 4 else Ver(f"{self.year + 1}.1")

    def prev(self) -> "Ver":
        return Ver(f"{self.year}.{self.q - 1}") if self.q > 1 else Ver(f"{self.year - 1}.4")

    @property
    def start_date(self) -> str:
        month = (self.q - 1) * 3 + 1
        return f"20{self.year:02d}-{month:02d}-01"

    @property
    def end_date(self) -> str:
        month = self.q * 3
        year  = 2000 + self.year
        last  = monthrange(year, month)[1]
        return f"20{self.year:02d}-{month:02d}-{last:02d}"


# ---------------------------------------------------------------------------
# Config / auth helpers
# ---------------------------------------------------------------------------

def require_config(parent_id: str) -> None:
    missing = [name for name, val in (
        ("CONFLUENCE_BASE_URL",  CONFLUENCE_BASE),
        ("CONFLUENCE_SPACE_KEY", SPACE_KEY),
        ("CONFLUENCE_TOKEN",     os.environ.get("CONFLUENCE_TOKEN", "")),
    ) if not val]
    if missing:
        sys.exit("Error: missing configuration: " + ", ".join(missing)
                 + " (set as environment variables or in a .env file)")
    if not parent_id:
        sys.exit("Error: parent page ID required: pass --parent-id or set CONFLUENCE_PARENT_PAGE_ID")


def get_headers() -> dict:
    token = os.environ["CONFLUENCE_TOKEN"]
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


# ---------------------------------------------------------------------------
# Confluence API helpers
# ---------------------------------------------------------------------------

def fetch_page(headers: dict, page_id: str) -> dict:
    resp = requests.get(
        f"{CONFLUENCE_BASE}/rest/api/content/{page_id}",
        headers=headers,
        params={"expand": "body.storage,ancestors,space,version"},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()


def find_page_by_title(headers: dict, title: str) -> Optional[dict]:
    resp = requests.get(
        f"{CONFLUENCE_BASE}/rest/api/content",
        headers=headers,
        params={"spaceKey": SPACE_KEY, "title": title, "expand": "version"},
        timeout=30,
    )
    resp.raise_for_status()
    results = resp.json().get("results", [])
    return results[0] if results else None


def create_page(headers: dict, parent_id: str, title: str, body_html: str) -> dict:
    resp = requests.post(
        f"{CONFLUENCE_BASE}/rest/api/content",
        json={
            "type":      "page",
            "title":     title,
            "space":     {"key": SPACE_KEY},
            "ancestors": [{"id": parent_id}],
            "body":      {"storage": {"value": body_html, "representation": "storage"}},
        },
        headers=headers,
        timeout=60,
    )
    if not resp.ok:
        print(f"  HTTP {resp.status_code}: {resp.text[:500]}")
        resp.raise_for_status()
    return resp.json()


def update_page(headers: dict, page_id: str, title: str, body_html: str, version: int) -> dict:
    resp = requests.put(
        f"{CONFLUENCE_BASE}/rest/api/content/{page_id}",
        json={
            "type":    "page",
            "title":   title,
            "version": {"number": version + 1},
            "body":    {"storage": {"value": body_html, "representation": "storage"}},
        },
        headers=headers,
        timeout=60,
    )
    if not resp.ok:
        print(f"  HTTP {resp.status_code}: {resp.text[:500]}")
        resp.raise_for_status()
    return resp.json()


# ---------------------------------------------------------------------------
# Body transformation
# ---------------------------------------------------------------------------

def _new_macro_id(_match) -> str:
    return f'ac:macro-id="{uuid.uuid4()}"'


def transform_body(body: str, from_ver: Ver, to_ver: Ver) -> str:
    """
    Generic transformation from any quarter page to the next.

    Version relationships used:
        prev_ver  = from_ver - 1   (e.g. 26.1 when from=26.2, to=26.3)
        from_ver                   (e.g. 26.2)  — was current, loses highlight
        to_ver                     (e.g. 26.3)  — becomes current (blue)
        next_ver  = to_ver + 1     (e.g. 26.4)  — becomes upcoming (orange)
    """
    prev_ver = from_ver.prev()
    next_ver = to_ver.next()

    # ── sprint dates ─────────────────────────────────────────────────────────
    body = body.replace(
        f'datetime="{from_ver.start_date}"',
        f'datetime="{to_ver.start_date}"',
    )
    body = body.replace(
        f'datetime="{from_ver.end_date}"',
        f'datetime="{to_ver.end_date}"',
    )

    # ── deliverables table column highlights ─────────────────────────────────
    # from_ver was current (blue) → loses highlight
    body = body.replace(
        f'<th class="highlight-{COLOUR_CURRENT}" data-highlight-colour="{COLOUR_CURRENT}" scope="col">'
        f"{from_ver} Deliverables ( Completed ones are stricken out )</th>",
        f'<th scope="col">{from_ver} Deliverables ( Completed ones are stricken out )</th>',
    )
    # to_ver was upcoming (orange) → becomes current (blue)
    body = body.replace(
        f'<th class="highlight-{COLOUR_NEXT}" data-highlight-colour="{COLOUR_NEXT}" scope="col">'
        f"{to_ver} Deliverables ( Completed ones are stricken out )</th>",
        f'<th class="highlight-{COLOUR_CURRENT}" data-highlight-colour="{COLOUR_CURRENT}" scope="col">'
        f"{to_ver} Deliverables ( Completed ones are stricken out )</th>",
    )
    # next_ver had no highlight → becomes upcoming (orange)
    body = body.replace(
        f'<th scope="col">{next_ver} ( Completed ones are stricken out )</th>',
        f'<th class="highlight-{COLOUR_NEXT}" data-highlight-colour="{COLOUR_NEXT}" scope="col">'
        f"{next_ver} Deliverables ( Completed ones are stricken out )</th>",
    )

    # ── deliverables section headings (prev_ver → from_ver) ─────────────────
    body = body.replace(
        f"{prev_ver} Deliverables ( Overall )",
        f"{from_ver} Deliverables ( Overall )",
    )
    body = body.replace(
        f"{prev_ver} Deliverables ( Individual ) - TBD",
        f"{from_ver} Deliverables ( Individual ) - TBD",
    )

    # ── sprint sub-labels (prev_ver.N → from_ver.N, e.g. 26.1.1 → 26.2.1) ──
    for n in range(1, 7):
        body = body.replace(f"{prev_ver}.{n}", f"{from_ver}.{n}")

    # ── Jira fixVersion references ────────────────────────────────────────────
    fv_from = re.escape(str(from_ver))
    body = re.sub(rf'fixVersion\s*=\s*{fv_from}',  f"fixVersion = {to_ver}",  body)
    body = re.sub(rf'fixVersion\s*!=\s*{fv_from}', f"fixVersion != {to_ver}", body)
    body = re.sub(rf'fixVersion={fv_from}\b',       f"fixVersion={to_ver}",    body)

    # ── URL-encoded fixVersion in jirachart JQL ───────────────────────────────
    body = body.replace(f"%3D%20{from_ver}%20", f"%3D%20{to_ver}%20")
    body = body.replace(f"%3D%20{from_ver}",    f"%3D%20{to_ver}")

    # ── "in from_ver" section labels ──────────────────────────────────────────
    body = body.replace(f"in {from_ver}", f"in {to_ver}")

    # ── placeholder deliverables text ────────────────────────────────────────
    # Replace any "place holder for XX.Y deliverables" with the new quarter
    body = re.sub(
        r'(place holder for )\d{2}\.\d( deliverables)',
        rf'\g<1>{to_ver}\2',
        body,
    )

    # ── "Only in X.Y" exclusion list ─────────────────────────────────────────
    # The fixVersion substitution above turns "!= from_ver" into "!= to_ver",
    # which contradicts "= to_ver" in the same query. Remove that clause.
    body = re.sub(
        rf'fixVersion\s*!=\s*{re.escape(str(to_ver))}\s*AND\s*',
        "",
        body,
    )

    # ── regenerate all macro IDs ──────────────────────────────────────────────
    body = re.sub(r'ac:macro-id="[^"]*"', _new_macro_id, body)

    return body


def diff_summary(original: str, transformed: str) -> str:
    """Quick stats on what changed."""
    lines = [
        f"  Original length : {len(original):,} chars",
        f"  Transformed     : {len(transformed):,} chars",
        f"  Macro IDs regen : {len(re.findall(r'ac:macro-id=', transformed))}",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Create or update a roadmap quarter page in Confluence.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 create_roadmap_page.py --to 26.4
  python3 create_roadmap_page.py --to 27.1
  python3 create_roadmap_page.py --to 26.4 --dry-run
  python3 create_roadmap_page.py --to 26.4 --source-id 1234567
  python3 create_roadmap_page.py --to 27.1 --parent-id 9876543 --yes
        """,
    )
    parser.add_argument("--to",        required=True,              metavar="YY.Q",
                        help="Target quarter to create, e.g. 26.4 or 27.1")
    parser.add_argument("--from",      dest="from_ver",            metavar="YY.Q",
                        help="Source quarter (default: previous quarter of --to)")
    parser.add_argument("--source-id", metavar="PAGE_ID",
                        help="Confluence page ID of the source quarter (auto-found if omitted)")
    parser.add_argument("--parent-id", default=PARENT_PAGE_ID,    metavar="PAGE_ID",
                        help="Parent page ID (default: $CONFLUENCE_PARENT_PAGE_ID)")
    parser.add_argument("--dry-run",   action="store_true",
                        help="Transform body and print stats, but do not publish to Confluence")
    parser.add_argument("--yes",       action="store_true",
                        help="Skip confirmation prompt")
    args = parser.parse_args()

    require_config(args.parent_id)

    to_ver   = Ver(args.to)
    from_ver = Ver(args.from_ver) if args.from_ver else to_ver.prev()

    print(f"  Source quarter : {from_ver}  ({from_ver.start_date} → {from_ver.end_date})")
    print(f"  Target quarter : {to_ver}  ({to_ver.start_date} → {to_ver.end_date})")
    print(f"  Parent page ID : {args.parent_id}")
    if args.dry_run:
        print("  Mode           : DRY RUN (no changes will be published)")
    print()

    headers = get_headers()

    # Step 1: find / fetch source page
    if args.source_id:
        source_id = args.source_id
        print(f"[1/4] Fetching source page {source_id} ({from_ver}) …")
    else:
        print(f"[1/4] Looking up source page '{from_ver}' in space {SPACE_KEY} …")
        found = find_page_by_title(headers, str(from_ver))
        if not found:
            sys.exit(f"Error: could not find a page titled '{from_ver}' in {SPACE_KEY}.\n"
                     f"       Pass --source-id <page_id> to specify it manually.")
        source_id = found["id"]
        print(f"      Found: ID {source_id}")

    source      = fetch_page(headers, source_id)
    source_body = source["body"]["storage"]["value"]
    print(f"      Body length: {len(source_body):,} chars")

    # Step 2: transform
    print(f"[2/4] Transforming body {from_ver} → {to_ver} …")
    new_body = transform_body(source_body, from_ver, to_ver)
    print(diff_summary(source_body, new_body))

    if args.dry_run:
        print("\n[DRY RUN] Skipping Confluence publish. Done.")
        return

    # Step 3: check if target already exists
    print(f"[3/4] Checking whether '{to_ver}' already exists in {SPACE_KEY} …")
    existing = find_page_by_title(headers, str(to_ver))

    action = "update" if existing else "create"
    if existing:
        print(f"      Page exists (ID {existing['id']}, v{existing['version']['number']}). Will UPDATE.")
    else:
        print(f"      Page not found. Will CREATE under parent {args.parent_id}.")

    # Confirm
    if not args.yes:
        answer = input(f"\nProceed to {action} '{to_ver}' in Confluence? [y/N] ").strip().lower()
        if answer != "y":
            print("Aborted.")
            return

    # Step 4: publish
    print(f"[4/4] Publishing '{to_ver}' …")
    if existing:
        ver    = existing["version"]["number"]
        result = update_page(headers, existing["id"], str(to_ver), new_body, ver)
    else:
        result = create_page(headers, args.parent_id, str(to_ver), new_body)

    page_id = result["id"]
    print()
    print("Done!")
    print(f"  Page ID : {page_id}")
    print(f"  URL     : {CONFLUENCE_BASE}/spaces/{SPACE_KEY}/pages/{page_id}/{to_ver}")


if __name__ == "__main__":
    main()
