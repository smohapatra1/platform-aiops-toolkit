"""
GCP Cloud Logging search — queries configured log-sink projects for IPs, hostnames, or keywords.
Uses google-cloud-logging Python library (no gcloud CLI required).

Install: pip install google-cloud-logging
Credentials: set GOOGLE_APPLICATION_CREDENTIALS=/path/to/sa.json
             or use workload identity / ADC if running on GCP.

Configure the project list either via the GCP_LOG_PROJECTS env var (comma-separated) or
by editing _OBS_PROJECTS below.
"""

import datetime
import os
import re
from collections import Counter

# ── Project config ─────────────────────────────────────────────────────────────
# Set GCP_LOG_PROJECTS in your environment (or .env) to a comma-separated list of project IDs.
# Example: GCP_LOG_PROJECTS=my-org-logs-prod,my-org-logs-preprod,my-org-logs-dev

_DEFAULT_PROJECTS = [
    "CHANGE_ME-logs-prod",
    "CHANGE_ME-logs-preprod",
    "CHANGE_ME-logs-dev",
]

def _load_projects():
    env = os.environ.get("GCP_LOG_PROJECTS", "")
    if env.strip():
        return [p.strip() for p in env.split(",") if p.strip()]
    return _DEFAULT_PROJECTS

_OBS_PROJECTS = _load_projects()

# Short labels for display. Auto-generated for projects not listed here.
_PROJECT_SHORT = {
    p: p.rsplit("-", 1)[-1]
    for p in _OBS_PROJECTS
}

_SEP = "─" * 78


def _ensure_library():
    """Import google-cloud-logging, auto-installing if missing. Returns True on success."""
    try:
        import google.cloud.logging  # noqa: F401
        return True
    except ImportError:
        pass
    import subprocess, sys
    try:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "--quiet", "google-cloud-logging"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        import google.cloud.logging  # noqa: F401
        return True
    except Exception:
        return False


def _to_rfc3339(ts):
    """Accept common date/time strings and return RFC3339 UTC for GCP filter."""
    ts = ts.strip().replace(" ", "T")
    if not ts.endswith("Z") and "+" not in ts:
        if len(ts) == 16:      # "2026-06-17T10:00"
            ts += ":00Z"
        elif len(ts) == 19:    # "2026-06-17T10:00:00"
            ts += "Z"
        else:
            ts += "Z"
    return ts


def _freshness_to_timestamp(freshness):
    """Convert '1h', '3d', '30m' to a UTC datetime cutoff string for filter."""
    m = re.match(r'^(\d+)([smhd])$', freshness.strip())
    if not m:
        return None
    n, unit = int(m.group(1)), m.group(2)
    delta = {
        's': datetime.timedelta(seconds=n),
        'm': datetime.timedelta(minutes=n),
        'h': datetime.timedelta(hours=n),
        'd': datetime.timedelta(days=n),
    }[unit]
    cutoff = datetime.datetime.utcnow() - delta
    return cutoff.strftime('%Y-%m-%dT%H:%M:%SZ')


def _extract_entry(entry, proj):
    """Pull timestamp, host, log source, message from a LogEntry object."""
    labels   = entry.labels or {}
    log_name = (entry.log_name or "").split("logs/")[-1]
    payload  = entry.payload

    if isinstance(payload, dict):
        host = labels.get("hostname") or payload.get("HostID", "")
        msg  = payload.get("message", "") or payload.get("msg", "") or str(payload)
    elif isinstance(payload, str):
        host = labels.get("hostname", "")
        msg  = payload
    else:
        host = labels.get("hostname", "")
        msg  = str(payload) if payload else ""

    ts = entry.timestamp
    ts_str = ts.strftime("%Y-%m-%d %H:%M:%S.%f")[:23] if ts else ""

    return {
        "timestamp":  ts_str,
        "project":    _PROJECT_SHORT.get(proj, proj),
        "host":       str(host).strip(),
        "log_source": log_name,
        "message":    str(msg).strip(),
        "severity":   str(entry.severity or "INFO"),
    }


def search_logs(query, projects=None, freshness="1h", start_time=None, end_time=None, limit=50):
    """
    Search GCP Cloud Logging across configured projects.

    Args:
        query:      IP address, hostname fragment, or any keyword string
        projects:   list of GCP project IDs (default: all configured projects)
        freshness:  relative window e.g. "1h", "3d" — ignored when start_time is set
        start_time: absolute start as "YYYY-MM-DD HH:MM" or RFC3339 (optional)
        end_time:   absolute end   as "YYYY-MM-DD HH:MM" or RFC3339 (optional)
        limit:      max entries per project

    Returns:
        (results, errors)
        results: list of dicts {timestamp, project, host, log_source, message, severity}
        errors:  list of per-project error strings
    """
    if not _ensure_library():
        return [], [
            "google-cloud-logging library not found and auto-install failed.\n"
            "             Fix: pip install google-cloud-logging"
        ]

    if projects is None:
        projects = _OBS_PROJECTS

    filter_parts = ['"{}"'.format(query.replace('"', '\\"')), '-logName:"cloudaudit"']

    if start_time:
        filter_parts.append('timestamp>="{}"'.format(_to_rfc3339(start_time)))
    else:
        cutoff = _freshness_to_timestamp(freshness)
        if cutoff:
            filter_parts.append('timestamp>="{}"'.format(cutoff))

    if end_time:
        filter_parts.append('timestamp<="{}"'.format(_to_rfc3339(end_time)))

    filter_expr = " AND ".join(filter_parts)

    all_results = []
    errors = []

    from google.cloud import logging as gcp_logging

    for proj in projects:
        try:
            client = gcp_logging.Client(project=proj)
            iterator = client.list_entries(
                resource_names=["projects/{}".format(proj)],
                filter_=filter_expr,
                order_by=gcp_logging.DESCENDING,
                page_size=min(limit, 1000),
            )
            count = 0
            for entry in iterator:
                if count >= limit:
                    break
                all_results.append(_extract_entry(entry, proj))
                count += 1
        except Exception as ex:
            msg = str(ex)
            if "PERMISSION_DENIED" in msg or "403" in msg:
                errors.append("{}: permission denied — check service account roles".format(
                    _PROJECT_SHORT.get(proj, proj)))
            elif "NOT_FOUND" in msg or "404" in msg:
                errors.append("{}: project not found or not accessible".format(
                    _PROJECT_SHORT.get(proj, proj)))
            else:
                errors.append("{}: {}".format(_PROJECT_SHORT.get(proj, proj), msg[:150]))

    all_results.sort(key=lambda x: x["timestamp"], reverse=True)
    return all_results, errors


def print_log_results(results, errors, query, limit=100):
    """Print search results in a readable format."""
    print("\n{}".format(_SEP))
    print(" GCP LOG SEARCH  query={!r}".format(query))
    print(_SEP)

    if errors:
        for err in errors:
            print("  [!] {}".format(err))
        if errors:
            print()

    if not results:
        print("  No results found across configured projects.")
        return

    proj_counts = Counter(r["project"] for r in results)
    print("  {} entries found  ({})".format(
        len(results),
        "  ".join("[{}] {}".format(p, c) for p, c in proj_counts.most_common()),
    ))
    print()

    prev_proj = None
    for r in results[:limit]:
        if r["project"] != prev_proj:
            print("  ── {} ──".format(r["project"].upper()))
            prev_proj = r["project"]
        host_str = "  {}".format(r["host"]) if r["host"] else ""
        print("  [{}]{} {}".format(r["timestamp"], host_str, r["log_source"]))
        msg = r["message"]
        if len(msg) > 400:
            idx = msg.lower().find(query.lower())
            if idx != -1:
                start = max(0, idx - 80)
                end   = min(len(msg), idx + len(query) + 180)
                msg   = ("..." if start else "") + msg[start:end] + ("..." if end < len(msg) else "")
        print("    {}".format(msg))
        print()
