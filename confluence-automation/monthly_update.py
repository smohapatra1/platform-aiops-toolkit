#!/usr/bin/env python3
"""
Manages monthly all-hands update pages in Confluence, including an AWS billing
section sourced from Cost Explorer and DORA/pipeline metrics from DX.

Usage:
  # Create a new month's page (copies previous month + injects billing + metrics)
  python3 monthly_update.py <Month>

  # Refresh the billing section on an existing page
  python3 monthly_update.py --update-billing <Month>

Examples:
  python3 monthly_update.py July
  python3 monthly_update.py --update-billing June

Environment variables (or .env file):
  CONFLUENCE_BASE_URL       Base URL of your Confluence instance
  CONFLUENCE_TOKEN          Personal access token
  CONFLUENCE_SPACE_KEY      Space key for your team space
  CONFLUENCE_PARENT_PAGE_ID Parent page ID for monthly updates
  WIKI_PAGE_PREFIX          Page title prefix (e.g. "Team Monthly Update")

  AWS_PROFILE               AWS profile with Cost Explorer read access (or set key/secret below)
  AWS_ACCESS_KEY_ID_NONPROD Non-prod account access key (optional — uses profile if unset)
  AWS_SECRET_ACCESS_KEY_NONPROD
  AWS_ACCESS_KEY_ID_PROD    Prod account access key (optional)
  AWS_SECRET_ACCESS_KEY_PROD

  DX_TEAM_ID                DX platform team ID (numeric string)
  DX_SESSION_COOKIE         Session cookie for DX API (browser-based auth)

  BILLING_START             Cost Explorer start date, e.g. 2025-01-01
  BILLING_END               Cost Explorer end date (exclusive), e.g. 2026-07-01
"""

import os
import re
import sys
import requests
from datetime import date
from pathlib import Path
from typing import Dict, List, Optional

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
except ImportError:
    print("boto3 is required: pip install boto3")
    sys.exit(1)

# ── Confluence config ─────────────────────────────────────────────────────────

CONFLUENCE_BASE = os.environ.get("CONFLUENCE_BASE_URL", "https://your-wiki.your-company.com")
PARENT_PAGE_ID  = os.environ.get("CONFLUENCE_PARENT_PAGE_ID", "CHANGE_ME")
SPACE_KEY       = os.environ.get("CONFLUENCE_SPACE_KEY", "CHANGE_ME")
PAGE_PREFIX     = os.environ.get("WIKI_PAGE_PREFIX", "Team Monthly Update")

MONTHS = [
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December"
]

# ── AWS / billing config ──────────────────────────────────────────────────────

BILLING_START = os.environ.get("BILLING_START", "2025-01-01")
BILLING_END   = os.environ.get("BILLING_END",   "2026-07-01")   # exclusive upper bound
TOP_SERVICES  = 15    # show top N services; rest collapsed into "Other"

_C_HIGH  = "#ffe8e8"   # light red   — high spend
_C_MID   = "#fff8e1"   # light amber — moderate spend
_C_LOW   = "#f0faf2"   # light green — low spend
_C_TOTAL = "#e8f0fe"   # light blue  — TOTAL row
_C_UP    = "#ffe8e8"
_C_DOWN  = "#f0faf2"

# ── DX config ─────────────────────────────────────────────────────────────────

DX_TEAM_ID = os.environ.get("DX_TEAM_ID", "CHANGE_ME")

DX_REPORT_URL  = "https://app.getdx.com/report/dora?interval=w&period=l2w&teams={t}".format(t=DX_TEAM_ID)
DX_API_ENDPOINTS = {
    "deploy_freq":    "/reports/api/deploy_frequency_by_service/overall",
    "merge_to_deploy":"/reports/api/merge_to_deploy_by_service/overall",
    "change_failure": "/reports/api/change_fail_by_service/overall",
    "time_to_recover":"/reports/api/time_to_recover/overall",
}

DX_PIPELINE_REPORT_URL = "https://app.getdx.com/report/pipelines?period=l3m&teams={t}".format(t=DX_TEAM_ID)
DX_PIPELINE_ENDPOINTS  = {
    "success_rate": "/reports/api/build_success_rate/overall",
    "wait_time":    "/reports/api/build_wait_time/overall",
    "num_builds":   "/reports/api/number_of_builds/overall",
}

DX_CODE_REVIEW_URL = "https://app.getdx.com/report/code-review?period=l3m"
DX_CODE_REVIEW_ENDPOINTS = {
    "pr_cycle_time":        "/reports/api/pr_cycle_time/overall",
    "review_turnaround":    "/reports/api/review_turnaround/overall",
    "time_to_first_review": "/reports/api/time_to_first_review/overall",
    "pr_size":              "/reports/api/pr_size/overall",
    "prs_merged":           "/reports/api/prs_merged/overall",
    "pr_throughput":        "/reports/api/pr_throughput/overall",
}

# ── AWS Cost Explorer ─────────────────────────────────────────────────────────

def _get_monthly_costs(access_key: str, secret_key: str, label: str) -> Optional[Dict]:
    """Query Cost Explorer for monthly unblended cost grouped by SERVICE."""
    try:
        client = boto3.client(
            "ce",
            region_name="us-east-1",
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
        )
        resp = client.get_cost_and_usage(
            TimePeriod={"Start": BILLING_START, "End": BILLING_END},
            Granularity="MONTHLY",
            Metrics=["UnblendedCost"],
            GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
        )
    except (ClientError, NoCredentialsError) as exc:
        print(f"  [{label}] Cost Explorer error: {exc}")
        return None
    except Exception as exc:
        print(f"  [{label}] Unexpected error: {exc}")
        return None

    months: List[str] = []
    services: Dict[str, Dict[str, float]] = {}

    for period in resp.get("ResultsByTime", []):
        month = period["TimePeriod"]["Start"][:7]
        months.append(month)
        for group in period.get("Groups", []):
            svc = group["Keys"][0]
            amt = float(group["Metrics"]["UnblendedCost"]["Amount"])
            if amt > 0:
                services.setdefault(svc, {})[month] = amt

    return {"months": months, "services": services}


# ── HTML formatting ───────────────────────────────────────────────────────────

def _usd(amount: float) -> str:
    return f"${amount:,.2f}"


def _cell_bg(amount: float, col_max: float) -> str:
    if col_max == 0 or amount == 0:
        return ""
    ratio = amount / col_max
    if ratio >= 0.75:
        return f" style=\"background-color:{_C_HIGH};\""
    if ratio >= 0.40:
        return f" style=\"background-color:{_C_MID};\""
    return f" style=\"background-color:{_C_LOW};\""


def _trend_cell(prev: float, curr: float) -> str:
    if prev == 0:
        return "<td style=\"text-align:center;\">—</td>"
    pct = (curr - prev) / prev * 100
    if abs(pct) < 0.5:
        return "<td style=\"text-align:center;\">→ &nbsp;0%</td>"
    if pct > 0:
        return (
            f"<td style=\"background-color:{_C_UP};text-align:center;\">"
            f"↑ {pct:+.1f}%</td>"
        )
    return (
        f"<td style=\"background-color:{_C_DOWN};text-align:center;\">"
        f"↓ {pct:+.1f}%</td>"
    )


def _account_table(label: str, data: Optional[Dict], heading: str = "h3") -> str:
    if data is None:
        return (
            f"<{heading}>{label}</{heading}>"
            f"<p><em>Data unavailable — check credentials for this account.</em></p>"
        )

    months   = data["months"]
    services = data["services"]

    if not services:
        return f"<{heading}>{label}</{heading}><p><em>No cost data found for this period.</em></p>"

    totals = {svc: sum(v for v in services[svc].values()) for svc in services}
    ranked = sorted(totals, key=lambda s: totals[s], reverse=True)
    top    = ranked[:TOP_SERVICES]
    others = ranked[TOP_SERVICES:]

    col_max: Dict[str, float] = {m: 0.0 for m in months}
    for svc in top:
        for m in months:
            col_max[m] = max(col_max[m], services[svc].get(m, 0.0))

    _td_h = "style=\"background-color:#f0f4f8;color:#172b4d;font-weight:bold;border-bottom:2px solid #c8d6e5;\""

    has_trend      = len(months) >= 2
    prev_m, last_m = (months[-2], months[-1]) if has_trend else (None, None)
    trend_header   = (
        f"<td {_td_h}>Trend ({prev_m} → {last_m})</td>"
        if has_trend else ""
    )
    month_ths = "".join(f"<td {_td_h}>{m}</td>" for m in months)

    rows  = ""
    grand: Dict[str, float] = {m: 0.0 for m in months}

    for svc in top:
        cells = ""
        for m in months:
            amt = services[svc].get(m, 0.0)
            grand[m] += amt
            cells += f"<td{_cell_bg(amt, col_max[m])}>{_usd(amt) if amt else '—'}</td>"
        trend = _trend_cell(
            services[svc].get(prev_m, 0.0),
            services[svc].get(last_m, 0.0),
        ) if has_trend else ""
        rows += f"<tr><td>{svc}</td>{cells}{trend}</tr>"

    if others:
        ocells = ""
        for m in months:
            amt = sum(services[s].get(m, 0.0) for s in others)
            grand[m] += amt
            ocells += f"<td>{_usd(amt) if amt else '—'}</td>"
        otrend = _trend_cell(
            sum(services[s].get(prev_m, 0.0) for s in others),
            sum(services[s].get(last_m, 0.0) for s in others),
        ) if has_trend else ""
        rows += (
            f"<tr><td><em>All other services ({len(others)})</em></td>"
            f"{ocells}{otrend}</tr>"
        )

    total_style = f"background-color:{_C_TOTAL};"
    tcells = "".join(
        f"<td style=\"{total_style}\"><strong>{_usd(grand[m])}</strong></td>"
        for m in months
    )
    ttrend = _trend_cell(grand.get(prev_m, 0.0), grand.get(last_m, 0.0)) if has_trend else ""
    rows += (
        f"<tr>"
        f"<td style=\"{total_style}\"><strong>TOTAL</strong></td>"
        f"{tcells}{ttrend}"
        f"</tr>"
    )

    heading_style = "style=\"background-color:#eef2f7;padding:4px 8px;border-radius:3px;color:#172b4d;\""
    return (
        f"<{heading} {heading_style}>{label}</{heading}>\n"
        f"<table><tbody>"
        f"<tr><td {_td_h}>Service</td>{month_ths}{trend_header}</tr>"
        f"{rows}</tbody></table>"
    )


def _build_billing_html(nonprod: Optional[Dict], prod: Optional[Dict]) -> str:
    generated = date.today().strftime("%B %d, %Y")
    html = (
        f"<p><em>Monthly unblended cost by service &mdash; "
        f"{BILLING_START} to {BILLING_END[:7]} &mdash; "
        f"generated {generated}.</em></p>"
    )
    html += _account_table("NonProd Account", nonprod, heading="h4")
    html += _account_table("Prod Account",    prod,    heading="h4")
    return html


def _fetch_billing_html() -> str:
    nonprod_key    = os.environ.get("AWS_ACCESS_KEY_ID_NONPROD", "")
    nonprod_secret = os.environ.get("AWS_SECRET_ACCESS_KEY_NONPROD", "")
    prod_key       = os.environ.get("AWS_ACCESS_KEY_ID_PROD", "")
    prod_secret    = os.environ.get("AWS_SECRET_ACCESS_KEY_PROD", "")

    nonprod_data = None
    if nonprod_key and nonprod_secret:
        print("  Fetching NonProd billing data...")
        nonprod_data = _get_monthly_costs(nonprod_key, nonprod_secret, "NonProd")
    else:
        print("  Skipping NonProd — AWS_ACCESS_KEY_ID_NONPROD not set.")

    prod_data = None
    if prod_key and prod_secret:
        print("  Fetching Prod billing data...")
        prod_data = _get_monthly_costs(prod_key, prod_secret, "Prod")
    else:
        print("  Skipping Prod — AWS_ACCESS_KEY_ID_PROD not set.")

    return _build_billing_html(nonprod_data, prod_data)


# ── DX helpers ────────────────────────────────────────────────────────────────

def _month_key(date_str: str) -> str:
    parts  = date_str[:7].split("-")
    months = {"01":"Jan","02":"Feb","03":"Mar","04":"Apr","05":"May","06":"Jun",
              "07":"Jul","08":"Aug","09":"Sep","10":"Oct","11":"Nov","12":"Dec"}
    return f"{months.get(parts[1], '?')}-{parts[0][2:]}"


def _dx_avg(data: dict) -> Optional[float]:
    vals = [v["value"] for v in data.get("time_series", {}).get("values", [])
            if v["value"] is not None]
    return sum(vals) / len(vals) if vals else None


def _monthly_agg(data: dict, use_sum: bool = False) -> Dict[str, float]:
    from collections import defaultdict
    buckets: Dict[str, List] = defaultdict(list)
    for v in data.get("time_series", {}).get("values", []):
        if v["value"] is not None:
            buckets[_month_key(v["date"])].append(float(v["value"]))
    if use_sum:
        return {m: sum(vs) for m, vs in buckets.items()}
    return {m: sum(vs)/len(vs) for m, vs in buckets.items()}


def _monthly_agg_key(data: dict, val_key: str = "value", use_sum: bool = False) -> Dict[str, Optional[float]]:
    from collections import defaultdict
    buckets: Dict[str, List] = defaultdict(list)
    for v in data.get("time_series", {}).get("values", []):
        raw = v.get(val_key)
        if raw is not None:
            buckets[_month_key(v["date"])].append(float(raw))
    if use_sum:
        return {m: sum(vs) for m, vs in buckets.items()}
    return {m: sum(vs)/len(vs) if vs else None for m, vs in buckets.items()}


def _dx_session_headers(referer: str = "") -> dict:
    cookie = os.environ.get("DX_SESSION_COOKIE", "")
    return {
        "accept": "application/json",
        "content-type": "application/json",
        "Cookie": cookie,
        "user-agent": "Mozilla/5.0",
        "x-requested-with": "XMLHttpRequest",
        **({"referer": referer} if referer else {}),
    }


def _fetch_dx_period(period: str) -> Dict[str, Optional[float]]:
    import time as _time
    hdrs    = _dx_session_headers()
    params  = {"teams": DX_TEAM_ID, "period": period, "interval": "w"}
    results = {}
    pending = dict(DX_API_ENDPOINTS)
    for _ in range(10):
        if not pending:
            break
        _time.sleep(2)
        for name, path in list(pending.items()):
            try:
                r = requests.get(f"https://app.getdx.com{path}", headers=hdrs,
                                 params=params, timeout=10)
                d = r.json()
                if not d.get("wait"):
                    results[name] = _dx_avg(d)
                    del pending[name]
            except Exception:
                del pending[name]
    return results


def _dx_fmt_freq(v):  return f"{v:.1f}/week" if v is not None else "—"
def _dx_fmt_secs(v):
    if v is None: return "—"
    h = v / 3600
    if h < 1:  return f"{v/60:.0f} min"
    if h < 24: return f"{h:.1f} hrs"
    return f"{h/24:.1f} days"
def _dx_fmt_pct(v): return f"{v:.0f}%" if v is not None else "—"


def _fetch_dx_dora() -> Optional[Dict[str, Dict[str, str]]]:
    if not os.environ.get("DX_SESSION_COOKIE"):
        return None
    try:
        print("  Fetching previous month DORA from DX...")
        prev = _fetch_dx_period("previous_month")
        print("  Fetching last month DORA from DX...")
        last = _fetch_dx_period("last_month")
        # Determine month labels dynamically
        from datetime import date as _date
        today = _date.today()
        _mn = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"]
        def _lbl(n):
            m = (today.month - 1 - n) % 12
            y = today.year - ((today.month - 1 - n) < 0)
            return f"{_mn[m]}-{str(y)[2:]}"
        prev_lbl = _lbl(1)
        last_lbl = _lbl(0)
        return {
            prev_lbl: {
                "deploy_freq":    _dx_fmt_freq(prev.get("deploy_freq")),
                "merge_to_deploy":_dx_fmt_secs(prev.get("merge_to_deploy")),
                "change_failure": _dx_fmt_pct(prev.get("change_failure")),
                "time_to_recover":_dx_fmt_secs(prev.get("time_to_recover")),
            },
            last_lbl: {
                "deploy_freq":    _dx_fmt_freq(last.get("deploy_freq")),
                "merge_to_deploy":_dx_fmt_secs(last.get("merge_to_deploy")),
                "change_failure": _dx_fmt_pct(last.get("change_failure")),
                "time_to_recover":_dx_fmt_secs(last.get("time_to_recover")),
            },
        }
    except Exception as e:
        print(f"  DX DORA fetch failed: {e}")
        return None


# Update these static fallback values from your DX dashboard each month
DORA_STATIC: Dict[str, Dict[str, str]] = {
    # "Mar-26": {"deploy_freq": "9.8/week", "merge_to_deploy": "40.3 hrs", "change_failure": "—", "time_to_recover": "—"},
    # "Apr-26": {"deploy_freq": "4.0/week", "merge_to_deploy": "3.9 days", "change_failure": "—", "time_to_recover": "12.3 days"},
}

DORA_MONTHS = []   # populated dynamically in _build_dora_section

DORA_METRIC_DEFS = [
    ("deploy_freq",    "🚀 Deployment Frequency", "How often code is deployed to production",        False, "Elite: Multiple/day  |  High: Daily  |  Medium: Weekly  |  Low: Monthly"),
    ("merge_to_deploy","🔀 Merge to Deploy",       "Time from merge to production deployment",         True,  "Elite: &lt;1hr  |  High: &lt;1day  |  Medium: 1–7 days  |  Low: &gt;6 months"),
    ("change_failure", "❌ Change Failure Rate",   "% of deployments causing a failure in production", True,  "Elite: 0–5%  |  High: 5–10%  |  Medium: 10–15%  |  Low: &gt;15%"),
    ("time_to_recover","🔧 MTTR",                  "Mean time to recover from a production failure",   True,  "Elite: &lt;1hr  |  High: &lt;1day  |  Medium: 1–7 days  |  Low: &gt;6 months"),
]


def _dora_trend(prev: str, curr: str, worse_when_up: bool):
    if "—" in (prev, "") or "—" in (curr, ""):
        return "—", "#f8f9fa"
    import re as _re
    pn = _re.search(r"[\d.]+", prev or "")
    cn = _re.search(r"[\d.]+", curr or "")
    if not pn or not cn:
        return "—", "#f8f9fa"
    pv, cv = float(pn.group()), float(cn.group())
    if abs(cv - pv) < 0.01:
        return "→ same", "#f8f9fa"
    if cv > pv:
        return f"↑ {cv-pv:.1f}", "#ffd6d6" if worse_when_up else "#d4edda"
    return f"↓ {pv-cv:.1f}", "#d4edda" if worse_when_up else "#ffd6d6"


def _build_dora_section(monthly_data: Optional[Dict] = None) -> str:
    generated = date.today().strftime("%B %d, %Y")
    safe_url  = DX_REPORT_URL.replace("&", "&amp;")

    data = {m: dict(v) for m, v in DORA_STATIC.items()}
    if monthly_data:
        for month, vals in monthly_data.items():
            data.setdefault(month, {}).update(vals)

    dora_months = sorted(data.keys())

    _td_h   = "style=\"background-color:#f0f4f8;color:#172b4d;font-weight:bold;border-bottom:2px solid #c8d6e5;\""
    _td_lb  = "style=\"font-weight:bold;\""
    _td_sm  = "style=\"font-size:0.85em;color:#555;\""
    _td_na  = "style=\"text-align:center;color:#aaa;\""
    _td_val = "style=\"text-align:center;font-weight:bold;\""

    month_ths = "".join(f"<td {_td_h}>{m}</td>" for m in dora_months)
    trend_cols = ""
    if len(dora_months) >= 2:
        trend_cols = f"<td {_td_h}>Trend ({dora_months[-2]} → {dora_months[-1]})</td>"
    header = (
        f"<tr><td {_td_h}>Metric</td><td {_td_h}>Description</td>"
        f"{month_ths}{trend_cols}"
        f"<td {_td_h}>DORA Benchmark</td></tr>"
    )

    rows = ""
    for key, name, desc, worse_when_up, bench in DORA_METRIC_DEFS:
        cells = ""
        for m in dora_months:
            val   = data.get(m, {}).get(key, "—")
            style = _td_na if val == "—" else _td_val
            cells += f"<td {style}>{val}</td>"

        trend = ""
        if len(dora_months) >= 2:
            prev_val = data.get(dora_months[-2], {}).get(key, "—")
            curr_val = data.get(dora_months[-1], {}).get(key, "—")
            sym, tbg = _dora_trend(prev_val, curr_val, worse_when_up)
            trend = f"<td style=\"text-align:center;background-color:{tbg};\">{sym}</td>"

        rows += f"<tr><td {_td_lb}>{name}</td><td>{desc}</td>{cells}{trend}<td {_td_sm}>{bench}</td></tr>"

    source = "Live from DX" if monthly_data else "DX (static fallback — update DORA_STATIC in script)"
    return (
        f'<p><em>Source: <a href="{safe_url}">DX DORA Report</a>'
        f' &mdash; {source} &mdash; generated {generated}.</em></p>'
        f"<table><tbody>{header}{rows}</tbody></table>"
    )


# ── Pipeline metrics ──────────────────────────────────────────────────────────

PIPELINE_METRIC_DEFS = [
    ("success_rate", "✅ Build Success Rate", "% of pipeline runs that pass",                  True,  "pct"),
    ("wait_time",    "⏳ Build Wait Time",    "Avg time waiting in queue before build starts",  False, "mins"),
    ("num_builds",   "🔨 Number of Builds",  "Total pipeline runs triggered",                  False, "int"),
]


def _fmt_pipeline(val: Optional[float], fmt: str) -> str:
    if val is None: return "—"
    if fmt == "pct":  return f"{val:.1f}%"
    if fmt == "mins": return f"{val/60:.1f} min"
    if fmt == "int":  return f"{val:.0f}"
    return str(val)


def _success_rate_color(val: Optional[float]) -> str:
    if val is None: return ""
    if val >= 95: return "#d4edda"
    if val >= 80: return "#fff3cd"
    return "#ffd6d6"


def _fetch_dx_pipeline() -> Optional[Dict]:
    if not os.environ.get("DX_SESSION_COOKIE"):
        return None
    import time as _time
    hdrs    = _dx_session_headers(referer=DX_PIPELINE_REPORT_URL)
    params  = {"teams": DX_TEAM_ID, "period": "l3m", "interval": "w"}
    results = {}
    pending = dict(DX_PIPELINE_ENDPOINTS)
    print("  Fetching pipeline metrics from DX...")
    for _ in range(10):
        if not pending: break
        _time.sleep(2)
        for name, path in list(pending.items()):
            try:
                r = requests.get(f"https://app.getdx.com{path}", headers=hdrs, params=params, timeout=10)
                d = r.json()
                if r.status_code == 404 or not d.get("wait"):
                    raw = d if r.status_code == 200 else {}
                    results[name] = _monthly_agg(raw, use_sum=(name == "num_builds"))
                    del pending[name]
            except Exception:
                del pending[name]

    out: Dict[str, Dict[str, str]] = {}
    for key, _, _, _, fmt in PIPELINE_METRIC_DEFS:
        months = sorted(results.get(key, {}).keys())
        for month in months:
            v = results.get(key, {}).get(month)
            out.setdefault(month, {})[key]           = _fmt_pipeline(v, fmt)
            out.setdefault(month, {})[f"_raw_{key}"] = v
    return out if out else None


def _build_pipeline_section(monthly_data: Optional[Dict] = None) -> str:
    generated = date.today().strftime("%B %d, %Y")
    safe_url  = DX_PIPELINE_REPORT_URL.replace("&", "&amp;")

    pipeline_months = sorted(monthly_data.keys()) if monthly_data else []

    _td_h  = "style=\"background-color:#f0f4f8;color:#172b4d;font-weight:bold;border-bottom:2px solid #c8d6e5;\""
    _td_lb = "style=\"font-weight:bold;\""
    _td_na = "style=\"text-align:center;color:#aaa;\""
    _td_v  = "style=\"text-align:center;font-weight:bold;\""

    month_ths = "".join(f"<td {_td_h}>{m}</td>" for m in pipeline_months)
    trend_col = ""
    if len(pipeline_months) >= 2:
        trend_col = f"<td {_td_h}>Trend ({pipeline_months[-2]} → {pipeline_months[-1]})</td>"
    header = (
        f"<tr><td {_td_h}>Metric</td><td {_td_h}>Description</td>"
        f"{month_ths}{trend_col}</tr>"
    )

    rows = ""
    for key, name, desc, worse_when_up, fmt in PIPELINE_METRIC_DEFS:
        cells = ""
        for m in pipeline_months:
            val     = monthly_data.get(m, {}).get(key, "—") if monthly_data else "—"
            raw_val = monthly_data.get(m, {}).get(f"_raw_{key}") if monthly_data else None
            if val == "—":
                cells += f"<td {_td_na}>—</td>"
            elif key == "success_rate":
                bg = _success_rate_color(raw_val)
                cells += f"<td style=\"text-align:center;font-weight:bold;background-color:{bg};\">{val}</td>"
            else:
                cells += f"<td {_td_v}>{val}</td>"

        trend = ""
        if len(pipeline_months) >= 2:
            prev_raw = monthly_data.get(pipeline_months[-2], {}).get(f"_raw_{key}") if monthly_data else None
            curr_raw = monthly_data.get(pipeline_months[-1], {}).get(f"_raw_{key}") if monthly_data else None
            sym, tbg = _dora_trend(
                _fmt_pipeline(prev_raw, fmt) if prev_raw is not None else "—",
                _fmt_pipeline(curr_raw, fmt) if curr_raw is not None else "—",
                worse_when_up,
            )
            trend = f"<td style=\"text-align:center;background-color:{tbg};\">{sym}</td>"

        rows += f"<tr><td {_td_lb}>{name}</td><td>{desc}</td>{cells}{trend}</tr>"

    source = "Live from DX" if monthly_data else "DX (not available — set DX_SESSION_COOKIE)"
    return (
        f'<p><em>Source: <a href="{safe_url}">DX Pipeline Report</a>'
        f' (last 3 months) &mdash; {source} &mdash; generated {generated}.</em></p>'
        f"<table><tbody>{header}{rows}</tbody></table>"
    )


# ── Code review metrics ───────────────────────────────────────────────────────

CODE_REVIEW_METRIC_DEFS = [
    ("prs_merged",           "🔀 PRs Merged",           "Total pull requests merged",                              False, "int"),
    ("pr_cycle_time",        "🔄 PR Cycle Time",         "Avg time from PR open to merge",                         True,  "duration"),
    ("time_to_first_review", "👀 Time to First Review",  "Avg time until first review comment",                    True,  "duration"),
    ("review_turnaround",    "⚡ Review Turnaround",     "Avg time reviewers take to respond after being pinged",  True,  "duration"),
    ("pr_size",              "📐 PR Size",               "Avg lines changed per PR (smaller = easier to review)",  False, "lines"),
    ("pr_throughput",        "📈 PR Throughput",         "Avg PRs merged per developer per week",                  False, "decimal"),
]


def _fmt_cr(val: Optional[float], fmt: str) -> str:
    if val is None: return "—"
    if fmt == "duration":
        h = val / 3600
        if h < 1:  return f"{val/60:.0f} min"
        if h < 24: return f"{h:.1f} hrs"
        return f"{h/24:.1f} days"
    if fmt == "int":     return f"{val:.0f}"
    if fmt == "lines":   return f"{val:.0f} lines"
    if fmt == "decimal": return f"{val:.2f}"
    return str(val)


def _fetch_dx_code_review() -> Optional[Dict]:
    if not os.environ.get("DX_SESSION_COOKIE"):
        return None
    import time as _time
    hdrs    = _dx_session_headers(referer=DX_CODE_REVIEW_URL)
    params  = {"teams": DX_TEAM_ID, "period": "l3m", "interval": "w"}
    raw     = {}
    pending = dict(DX_CODE_REVIEW_ENDPOINTS)
    print("  Fetching code review metrics from DX...")
    for _ in range(10):
        if not pending: break
        _time.sleep(2)
        for name, path in list(pending.items()):
            try:
                r = requests.get(f"https://app.getdx.com{path}", headers=hdrs, params=params, timeout=10)
                d = r.json()
                if r.status_code == 404 or not d.get("wait"):
                    raw[name] = d if r.status_code == 200 else {}
                    del pending[name]
            except Exception:
                del pending[name]

    out: Dict[str, Dict] = {}
    for key, _, _, _, fmt in CODE_REVIEW_METRIC_DEFS:
        data = raw.get(key, {})
        if key == "pr_throughput":
            monthly = _monthly_agg_key(data, val_key="unweighted")
        elif key in ("prs_merged",):
            monthly = _monthly_agg_key(data, use_sum=True)
        else:
            monthly = _monthly_agg_key(data)
        for m in sorted(monthly.keys()):
            v = monthly.get(m)
            out.setdefault(m, {})[key]           = _fmt_cr(v, fmt)
            out.setdefault(m, {})[f"_raw_{key}"] = v
    return out if out else None


def _build_code_review_section(monthly_data: Optional[Dict] = None) -> str:
    generated = date.today().strftime("%B %d, %Y")
    safe_url  = DX_CODE_REVIEW_URL.replace("&", "&amp;")

    cr_months = sorted(monthly_data.keys()) if monthly_data else []

    _td_h  = "style=\"background-color:#f0f4f8;color:#172b4d;font-weight:bold;border-bottom:2px solid #c8d6e5;\""
    _td_lb = "style=\"font-weight:bold;\""
    _td_na = "style=\"text-align:center;color:#aaa;\""
    _td_v  = "style=\"text-align:center;font-weight:bold;\""

    month_ths = "".join(f"<td {_td_h}>{m}</td>" for m in cr_months)
    trend_col = ""
    if len(cr_months) >= 2:
        trend_col = f"<td {_td_h}>Trend ({cr_months[-2]} → {cr_months[-1]})</td>"
    header = (
        f"<tr><td {_td_h}>Metric</td><td {_td_h}>Description</td>"
        f"{month_ths}{trend_col}</tr>"
    )

    rows = ""
    for key, name, desc, worse_when_up, fmt in CODE_REVIEW_METRIC_DEFS:
        cells = ""
        for m in cr_months:
            val = monthly_data.get(m, {}).get(key, "—") if monthly_data else "—"
            style = _td_na if val == "—" else _td_v
            cells += f"<td {style}>{val}</td>"

        trend = ""
        if len(cr_months) >= 2:
            prev_raw = monthly_data.get(cr_months[-2], {}).get(f"_raw_{key}") if monthly_data else None
            curr_raw = monthly_data.get(cr_months[-1], {}).get(f"_raw_{key}") if monthly_data else None
            sym, tbg = _dora_trend(
                _fmt_cr(prev_raw, fmt) if prev_raw is not None else "—",
                _fmt_cr(curr_raw, fmt) if curr_raw is not None else "—",
                worse_when_up,
            )
            trend = f"<td style=\"text-align:center;background-color:{tbg};\">{sym}</td>"

        rows += f"<tr><td {_td_lb}>{name}</td><td>{desc}</td>{cells}{trend}</tr>"

    source = "Live from DX" if monthly_data else "DX (not available — set DX_SESSION_COOKIE)"
    return (
        f'<p><em>Source: <a href="{safe_url}">DX Code Review Report</a>'
        f' (last 3 months) &mdash; {source} &mdash; generated {generated}.</em></p>'
        f"<table><tbody>{header}{rows}</tbody></table>"
    )


# ── Confluence helpers ────────────────────────────────────────────────────────

_H2_STYLE = "background-color:#c9dff7;border-left:5px solid #2d7dd2;padding:5px 12px;color:#0d2b4e;"
_H3_STYLE = "background-color:#ddeaf7;border-left:4px solid #5a9fd4;padding:4px 10px;color:#1a3a5c;"


def _get_headers() -> dict:
    token = os.environ.get("CONFLUENCE_TOKEN", "")
    if not token:
        print("Error: CONFLUENCE_TOKEN environment variable not set.")
        sys.exit(1)
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


def _get_page_by_title(headers: dict, space_key: str, title: str) -> Optional[dict]:
    url    = f"{CONFLUENCE_BASE}/rest/api/content"
    params = {"spaceKey": space_key, "title": title, "expand": "body.storage,version"}
    resp   = requests.get(url, params=params, headers=headers)
    resp.raise_for_status()
    results = resp.json().get("results", [])
    return results[0] if results else None


def _create_page(headers: dict, parent_id: str, space_key: str, title: str, body_html: str) -> dict:
    url     = f"{CONFLUENCE_BASE}/rest/api/content"
    payload = {
        "type":      "page",
        "title":     title,
        "space":     {"key": space_key},
        "ancestors": [{"id": parent_id}],
        "body":      {"storage": {"value": body_html, "representation": "storage"}},
    }
    resp = requests.post(url, json=payload, headers=headers)
    resp.raise_for_status()
    return resp.json()


def _update_page(headers: dict, page_id: str, title: str, body_html: str, current_version: int) -> dict:
    url     = f"{CONFLUENCE_BASE}/rest/api/content/{page_id}"
    payload = {
        "type":    "page",
        "title":   title,
        "version": {"number": current_version + 1},
        "body":    {"storage": {"value": body_html, "representation": "storage"}},
    }
    resp = requests.put(url, json=payload, headers=headers)
    resp.raise_for_status()
    return resp.json()


def _style_headings(body: str) -> str:
    def replace(m):
        tag     = m.group(1)
        attrs   = m.group(2)
        content = m.group(3)
        style   = _H2_STYLE if tag == "h2" else _H3_STYLE
        attrs   = re.sub(r'\s*style="[^"]*"', "", attrs).strip()
        open_tag = f'<{tag} style="{style}"' + (f" {attrs}" if attrs else "") + ">"
        return f"{open_tag}{content}</{tag}>"

    return re.sub(
        r'<(h[23])([^>]*)>(.*?)</h[23]>',
        replace,
        body,
        flags=re.DOTALL | re.IGNORECASE,
    )


def _is_dark(r: int, g: int, b: int) -> bool:
    return (0.299 * r + 0.587 * g + 0.114 * b) < 140


def _lighten(r: int, g: int, b: int, blend: float = 0.62) -> str:
    return f"rgb({int(r*(1-blend)+255*blend)},{int(g*(1-blend)+255*blend)},{int(b*(1-blend)+255*blend)})"


def _lighten_table_headers(body: str) -> str:
    def patch_td(m: re.Match) -> str:
        full    = m.group(0)
        style_m = re.search(r'style="([^"]*)"', full)
        if not style_m:
            return full
        style = style_m.group(1)
        bg_m  = re.search(r'background-color:\s*rgb\((\d+),\s*(\d+),\s*(\d+)\)', style)
        if not bg_m:
            return full
        r, g, b = int(bg_m.group(1)), int(bg_m.group(2)), int(bg_m.group(3))
        if not _is_dark(r, g, b):
            return full
        light_bg = _lighten(r, g, b)
        style = re.sub(r'background-color:\s*rgb\(\d+,\s*\d+,\s*\d+\)',
                       f"background-color:{light_bg}", style)
        style = re.sub(r'(?<!-)color:[^;]+;?', '', style)
        style = style.rstrip(";") + ";color:#172b4d;"
        return full[:style_m.start()] + f'style="{style}"' + full[style_m.end():]

    return re.sub(r'<td\b[^>]*>', patch_td, body)


# ── Section injection helpers ─────────────────────────────────────────────────

def _inject_billing_section(body: str, billing_html: str) -> str:
    body = re.compile(r'<h2[^>]*>AWS Billing[^<]*</h2>.*', re.DOTALL | re.IGNORECASE).sub("", body)
    m = re.compile(
        r'(<h3[^>]*>AWS Billing</h3>).*?(?=<hr\s*/?>|<h3[\s>])',
        re.DOTALL | re.IGNORECASE,
    ).search(body)
    if m:
        return body[:m.start()] + m.group(1) + billing_html + body[m.end():]
    return body + f"<h3>AWS Billing</h3>{billing_html}"


def _inject_dora_section(body: str, dora_html: str) -> str:
    existing = re.compile(
        r'(<h3[^>]*>.*?DORA.*?</h3>).*?(?=<hr\s*/?>|<h3[\s>])',
        re.DOTALL | re.IGNORECASE,
    )
    m = existing.search(body)
    if m:
        return body[:m.start()] + m.group(1) + dora_html + body[m.end():]
    after_billing = re.compile(
        r'(<h3[^>]*>AWS Billing</h3>.*?)(?=<hr\s*/?>|<h3[\s>])',
        re.DOTALL | re.IGNORECASE,
    )
    m = after_billing.search(body)
    if m:
        return body[:m.end()] + '<h3>📊 DORA Metrics</h3>' + dora_html + body[m.end():]
    return body + '<h3>📊 DORA Metrics</h3>' + dora_html


def _inject_pipeline_section(body: str, pipeline_html: str) -> str:
    heading = "<h3>📊 Pipeline Metrics</h3>"
    existing = re.compile(
        r'<h3[^>]*>.*?Pipeline Metrics.*?</h3>.*?(?=<hr\s*/?>|<h3[\s>])',
        re.DOTALL | re.IGNORECASE,
    )
    m = existing.search(body)
    if m:
        return body[:m.start()] + heading + pipeline_html + body[m.end():]
    after_dora = re.compile(
        r'(<h3[^>]*>.*?DORA.*?</h3>.*?)(?=<hr\s*/?>|<h3[\s>])',
        re.DOTALL | re.IGNORECASE,
    )
    m = after_dora.search(body)
    if m:
        return body[:m.end()] + heading + pipeline_html + body[m.end():]
    return body + heading + pipeline_html


def _inject_code_review_section(body: str, html: str) -> str:
    heading = "<h3>⚡ Code Review Efficiency</h3>"
    existing = re.compile(
        r'<h3[^>]*>.*?Code Review Efficiency.*?</h3>.*?(?=<hr\s*/?>|<h3[\s>])',
        re.DOTALL | re.IGNORECASE,
    )
    m = existing.search(body)
    if m:
        return body[:m.start()] + heading + html + body[m.end():]
    after = re.compile(
        r'(<h3[^>]*>.*?Pipeline Metrics.*?</h3>.*?)(?=<hr\s*/?>|<h3[\s>])',
        re.DOTALL | re.IGNORECASE,
    )
    m = after.search(body)
    if m:
        return body[:m.end()] + heading + html + body[m.end():]
    return body + heading + html


# ── Commands ──────────────────────────────────────────────────────────────────

def _resolve_month(raw: str) -> str:
    normalized = raw.strip().capitalize()
    if normalized not in MONTHS:
        print(f"Error: '{raw}' is not a valid month.")
        print(f"  Valid values: {', '.join(MONTHS)}")
        sys.exit(1)
    return normalized


def _previous_month(month: str) -> str:
    return MONTHS[MONTHS.index(month) - 1]


def cmd_create(month: str) -> None:
    year         = date.today().year
    new_title    = f"{PAGE_PREFIX} - {month}-{str(year)[2:]}"
    source_title = f"{PAGE_PREFIX} - {_previous_month(month)}-{str(year)[2:]}"
    headers      = _get_headers()

    if _get_page_by_title(headers, SPACE_KEY, new_title):
        print(f"Page already exists: '{new_title}'. Aborting to avoid duplicates.")
        sys.exit(1)

    print(f"Fetching source page: '{source_title}' ...")
    source = _get_page_by_title(headers, SPACE_KEY, source_title)
    if not source:
        print(f"Error: Could not find source page '{source_title}'.")
        sys.exit(1)
    print(f"  Found source page ID: {source['id']}")

    body = source["body"]["storage"]["value"]

    print("Fetching AWS billing data ...")
    body = _inject_billing_section(body, _fetch_billing_html())

    print("Fetching DORA metrics ...")
    body = _inject_dora_section(body, _build_dora_section(_fetch_dx_dora()))

    print("Fetching pipeline metrics ...")
    body = _inject_pipeline_section(body, _build_pipeline_section(_fetch_dx_pipeline()))

    print("Fetching code review metrics ...")
    body = _inject_code_review_section(body, _build_code_review_section(_fetch_dx_code_review()))

    body = _style_headings(body)
    body = _lighten_table_headers(body)

    print(f"Creating new page: '{new_title}' under parent ID {PARENT_PAGE_ID} ...")
    new_page = _create_page(headers, PARENT_PAGE_ID, SPACE_KEY, new_title, body)
    new_id   = new_page["id"]

    print(f"\nDone! New page created.")
    print(f"  Title : {new_title}")
    print(f"  ID    : {new_id}")
    print(f"  URL   : {CONFLUENCE_BASE}/wiki/spaces/{SPACE_KEY}/pages/{new_id}")


def cmd_update_billing(month: str) -> None:
    year    = date.today().year
    title   = f"{PAGE_PREFIX} - {month}-{str(year)[2:]}"
    headers = _get_headers()

    print(f"Fetching existing page: '{title}' ...")
    page = _get_page_by_title(headers, SPACE_KEY, title)
    if not page:
        print(f"Error: Could not find page '{title}'. Create it first.")
        sys.exit(1)

    page_id = page["id"]
    version = page["version"]["number"]
    print(f"  Found page ID: {page_id}  (version {version})")

    body = page["body"]["storage"]["value"]

    print("Fetching AWS billing data ...")
    body = _inject_billing_section(body, _fetch_billing_html())
    body = _inject_dora_section(body, _build_dora_section(_fetch_dx_dora()))
    body = _inject_pipeline_section(body, _build_pipeline_section(_fetch_dx_pipeline()))
    body = _inject_code_review_section(body, _build_code_review_section(_fetch_dx_code_review()))
    body = _style_headings(body)
    body = _lighten_table_headers(body)

    print(f"Updating page (version {version} → {version + 1}) ...")
    _update_page(headers, page_id, title, body, version)

    print(f"\nDone! Page refreshed.")
    print(f"  Title : {title}")
    print(f"  URL   : {CONFLUENCE_BASE}/wiki/spaces/{SPACE_KEY}/pages/{page_id}")


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    args = sys.argv[1:]
    if len(args) == 1 and not args[0].startswith("--"):
        cmd_create(_resolve_month(args[0]))
    elif len(args) == 2 and args[0] == "--update-billing":
        cmd_update_billing(_resolve_month(args[1]))
    else:
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
