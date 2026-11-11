#!/usr/bin/env python3
"""
Fetch and summarize the active Jira sprint for a given board, optionally with
AI-written analysis from Claude.

Usage:
    python3 jira_sprint_summary.py [--board 123] [--save]
    python3 jira_sprint_summary.py [--board 123] [--ai] [--save]

Configuration (environment variables, or KEY=VALUE lines in a .env file):

  Jira (required)
    JIRA_BASE_URL         e.g. https://jira.example.com
    JIRA_TOKEN            Personal access token (sent as a Bearer token)
    JIRA_BOARD_ID         Board ID (or pass --board)

  Report wording (optional)
    TEAM_NAME             Team name used in AI prompts (default: "engineering")
    ONCALL_PREFIX         Issue-summary prefix that marks oncall tickets
                          (default: "[ONCALL]")

  AI analysis, --ai (pick ONE backend)
    A) Anthropic API directly
         ANTHROPIC_API_KEY
    B) Claude on Vertex AI behind an OAuth client-credentials gateway
         LLM_GATEWAY_OAUTH_URL, LLM_GATEWAY_API_BASE, LLM_GATEWAY_PROJECT,
         LLM_GATEWAY_CLIENT_ID, LLM_GATEWAY_CLIENT_SECRET
         LLM_GATEWAY_REGION      (default: global)
         LLM_GATEWAY_USER_EMAIL  (optional, sent as a "user_email" header)
    LLM_MODEL               Model ID (default: claude-sonnet-4-6)

Never commit your .env file or tokens.
"""

import argparse
import base64
import json
import os
import sys
from collections import Counter
from datetime import date, timedelta
from pathlib import Path
from typing import Optional

try:
    import requests
except ImportError:
    print("Missing dependency: pip install requests")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CONFIG: dict[str, str] = {}   # populated by load_config() in main()


def load_env_file(path: Path) -> dict[str, str]:
    result = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        result[k.strip()] = v.strip().strip('"').strip("'")
    return result


def load_config(env_file: Optional[Path]) -> None:
    """Environment variables win over values from the env file."""
    file_vals = load_env_file(env_file) if env_file and env_file.exists() else {}
    CONFIG.clear()
    CONFIG.update(file_vals)
    CONFIG.update({k: v for k, v in os.environ.items() if v})


def cfg(name: str, default: str = "") -> str:
    return CONFIG.get(name, default)


def require(name: str) -> str:
    val = cfg(name)
    if not val:
        raise ValueError(f"{name} is not set (environment variable or .env file)")
    return val


def jira_base() -> str:
    return require("JIRA_BASE_URL").rstrip("/")


def team_name() -> str:
    return cfg("TEAM_NAME", "engineering")


def oncall_prefix() -> str:
    return cfg("ONCALL_PREFIX", "[ONCALL]")


# ---------------------------------------------------------------------------
# LLM backends
# ---------------------------------------------------------------------------

def _extract_text(data: dict) -> str:
    if "content" in data:
        return data["content"][0]["text"]
    if "predictions" in data:
        pred = data["predictions"][0]
        return pred.get("content", [{}])[0].get("text", str(pred))
    return str(data)


def _anthropic_llm(api_key: str):
    model = cfg("LLM_MODEL", "claude-sonnet-4-6")

    def call(messages: list, system: str = "", max_tokens: int = 1024) -> str:
        body = {
            "model":      model,
            "max_tokens": max_tokens,
            "messages":   messages,
            **({"system": system} if system else {}),
        }
        resp = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key":         api_key,
                "anthropic-version": "2023-06-01",
                "content-type":      "application/json",
            },
            json=body,
            timeout=90,
        )
        if not resp.ok:
            raise RuntimeError(f"HTTP {resp.status_code}: {resp.text[:300]}")
        return _extract_text(resp.json())

    return call


def _gateway_llm():
    """Claude on Vertex AI via an OAuth client-credentials gateway."""
    client_id     = require("LLM_GATEWAY_CLIENT_ID")
    client_secret = require("LLM_GATEWAY_CLIENT_SECRET")
    oauth_url     = require("LLM_GATEWAY_OAUTH_URL")
    api_base      = require("LLM_GATEWAY_API_BASE").rstrip("/")
    project       = require("LLM_GATEWAY_PROJECT")
    region        = cfg("LLM_GATEWAY_REGION", "global")
    user_email    = cfg("LLM_GATEWAY_USER_EMAIL")
    model         = cfg("LLM_MODEL", "claude-sonnet-4-6")

    basic = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    resp  = requests.post(
        oauth_url,
        data="grant_type=client_credentials",
        headers={
            "Content-Type":  "application/x-www-form-urlencoded",
            "Authorization": f"Basic {basic}",
        },
        timeout=15,
    )
    resp.raise_for_status()
    bearer = resp.json()["access_token"]

    endpoint = (
        f"{api_base}/v1/projects/{project}"
        f"/locations/{region}/publishers/anthropic"
        f"/models/{model}:rawPredict"
    )

    def call(messages: list, system: str = "", max_tokens: int = 1024) -> str:
        body = {
            "anthropic_version": "vertex-2023-10-16",
            "max_tokens":        max_tokens,
            "messages":          messages,
            **({"system": system} if system else {}),
        }
        headers = {
            "Authorization": f"Bearer {bearer}",
            "Content-Type":  "application/json",
        }
        if user_email:
            headers["user_email"] = user_email
        r = requests.post(endpoint, headers=headers, json=body, timeout=90)
        if not r.ok:
            raise RuntimeError(f"HTTP {r.status_code}: {r.text[:300]}")
        return _extract_text(r.json())

    return call


def get_llm():
    """Return call(messages, system, max_tokens) -> str for the configured backend."""
    api_key = cfg("ANTHROPIC_API_KEY")
    if api_key:
        return _anthropic_llm(api_key)
    return _gateway_llm()


# ---------------------------------------------------------------------------
# AI analysis
# ---------------------------------------------------------------------------

_SPRINT_ANALYSIS_SYSTEM = """\
You are an engineering manager writing a concise internal sprint review for the {team} team.
Given the sprint data, write:
1. A 2-3 sentence executive summary of the sprint.
2. **Key Wins** (3-5 bullets) — specific completed items worth highlighting by name.
3. **Watch List** (2-4 bullets) — in-progress or todo items that need attention before the sprint ends.
4. **Team Observations** (2-3 bullets) — workload balance, velocity, patterns.

Be specific — reference actual issue summaries, assignees, and numbers.
Use plain markdown. Keep the total under 350 words."""

_SUMMARY_NOTE_SYSTEM = """\
Write a 2-3 sentence executive paragraph summarizing a {team} sprint update.

Style (follow this pattern):
"Completed X items including <key themes>. Over the next two weeks, focus will be on <themes>. \
Future work will center on <themes>, which are currently at risk pending <reason>."

Output ONLY the paragraph. No headers, no bullets, no extra text."""

_STORY_SYSTEM = """\
Write the Sprint Story body for a {team} sprint review. \
Use plain markdown. No fenced code blocks.

Format (follow exactly):
[One sentence describing this sprint's main themes.]

✅ Completed Engineering Work (X Items)
[Category Name]
- [one sentence, past tense, max 15 words, no ticket IDs]
...

🚧 In Progress (X Items)
[Category Name]
- [one sentence, present tense, max 15 words]
...

⚠️ At Risk / Not Started (X Items)
[Category Name]
- [one sentence, present tense, max 15 words]
...

✅ On-Call Support
[One paragraph summarising oncall incidents resolved.]

Overall Story
[2-3 sentence paragraph tying completed work, in-progress focus, and at-risk items together.]

Rules:
- Use descriptive category names that fit the actual content (not a fixed list)
- Group closely related tasks into ONE bullet
- No ticket IDs, no jargon, no filler like "successfully" or "has been"
- Replace X with the actual item count for each section
- Output ONLY the formatted body above — no extra headings or commentary"""

_TIMELINE_SYSTEM = """\
Write a Work Timeline for a {team} sprint review, grouping tasks by \
completion horizon. Use plain markdown. No fenced code blocks.

Format (follow exactly):

✅ Completed Last Week (X Items)
[Category Name]
- [one sentence, past tense, max 15 words, no ticket IDs]
...
[If oncall_done_last_week is non-empty, end with one short paragraph summarising the oncall incidents.]

📅 Planned Completion in Next Two Weeks (X Items)
[Category Name]
- [one sentence, present tense, max 15 words]
...

🔭 Working On, Planned Completion Greater Than Two Weeks (X Items)
[Category Name]
- [one sentence, present tense, max 15 words]
...

Rules:
- "completed_last_week" items go ONLY in the first section.
- Classify every item in "in_progress" and "not_started" into the second or third section.
- If an item has a "duedate": on or before "two_weeks_out" -> second section, after it -> third.
- If no "duedate": judge from the work itself and its status. Small, nearly finished, or \
  well-scoped items -> second section. Large investigations, multi-environment rollouts, \
  upgrades, or architecture/feature work -> third section.
- Items with "status" To Do / Backlog / not started that are not due soon -> third section.
- Use descriptive category names that fit the actual content (not a fixed list)
- Group closely related tasks into ONE bullet
- No ticket IDs, no jargon, no filler like "successfully" or "has been"
- Replace X with the actual item count for each section (count tasks, not bullets)
- If a section has no items, still print its heading with "(0 Items)" and the line "- None"
- Output ONLY the formatted body above — no extra headings or commentary"""


def _system(prompt: str) -> str:
    return prompt.replace("{team}", team_name())


def ai_story_narrative(done: list, inprogress: list, todo: list, llm) -> dict:
    """Call Claude to generate the full Sprint Story body as markdown."""
    eng_done = [i for i in done       if not is_oncall(i)]
    oc_done  = [i for i in done       if     is_oncall(i)]
    eng_ip   = [i for i in inprogress if not is_oncall(i)]
    oc_ip    = [i for i in inprogress if     is_oncall(i)]

    data = {
        "completed":     [{"summary": i["summary"], "type": i.get("issuetype", "Task")}
                          for i in eng_done],
        "in_progress":   [{"summary": i["summary"], "type": i.get("issuetype", "Task")}
                          for i in eng_ip],
        "at_risk":       [{"summary": i["summary"], "type": i.get("issuetype", "Task")}
                          for i in todo if not is_oncall(i)],
        "oncall_done":   [{"summary": i["summary"]} for i in oc_done],
        "oncall_active": [{"summary": i["summary"]} for i in oc_ip],
    }
    raw = llm(
        [{"role": "user", "content": f"Tasks:\n{json.dumps(data, indent=2)}"}],
        system=_system(_STORY_SYSTEM),
        max_tokens=2048,
    )
    return {"story_md": raw}


def ai_timeline_narrative(sprint: dict, done: list, inprogress: list, todo: list, llm) -> str:
    """Call Claude to bucket work into last-week / next-two-weeks / longer-than-two-weeks."""
    today     = date.today()
    week_ago  = (today - timedelta(days=7)).isoformat()
    two_weeks = (today + timedelta(days=14)).isoformat()

    # Done: keep only items resolved in the last 7 days. No resolution date -> keep (can't rule out).
    recent   = [i for i in done if not i["resolved"] or i["resolved"] >= week_ago]
    eng_done = [i for i in recent if not is_oncall(i)]
    oc_done  = [i for i in recent if     is_oncall(i)]
    open_eng = [i for i in inprogress if not is_oncall(i)]
    todo_eng = [i for i in todo       if not is_oncall(i)]

    def _item(i, with_status=False):
        d = {"summary": i["summary"], "type": i.get("issuetype", "Task")}
        if i.get("duedate"):
            d["duedate"] = i["duedate"]
        if with_status:
            d["status"] = i["status"]
        return d

    data = {
        "today":                 today.isoformat(),
        "two_weeks_out":         two_weeks,
        "sprint_end":            sprint.get("endDate", "")[:10],
        "completed_last_week":   [_item(i) for i in eng_done],
        "oncall_done_last_week": [{"summary": i["summary"]} for i in oc_done],
        "in_progress":           [_item(i, True) for i in open_eng],
        "not_started":           [_item(i, True) for i in todo_eng],
    }
    return llm(
        [{"role": "user", "content": f"Tasks:\n{json.dumps(data, indent=2)}"}],
        system=_system(_TIMELINE_SYSTEM),
        max_tokens=2048,
    )


def generate_summary_note(done: list, inprogress: list, todo: list, llm) -> str:
    eng_done = [i for i in done       if not is_oncall(i)]
    oc_done  = [i for i in done       if     is_oncall(i)]
    eng_ip   = [i for i in inprogress if not is_oncall(i)]
    eng_todo = [i for i in todo       if not is_oncall(i)]

    done_str = "\n".join(f"- {i['summary']}" for i in eng_done) or "(none)"
    ip_str   = "\n".join(f"- {i['summary']}" for i in eng_ip)   or "(none)"
    todo_str = "\n".join(f"- {i['summary']}" for i in eng_todo) or "(none)"
    oc_line  = f"\nAlso resolved {len(oc_done)} oncall support incidents." if oc_done else ""

    prompt = (
        f"Completed ({len(eng_done)} engineering items):\n{done_str}{oc_line}\n\n"
        f"In progress / next two weeks:\n{ip_str}\n\n"
        f"Not started / at risk:\n{todo_str}"
    )
    return llm(
        [{"role": "user", "content": prompt}],
        system=_system(_SUMMARY_NOTE_SYSTEM),
        max_tokens=256,
    )


def ai_analyze_sprint(sprint: dict, todo: list, inprogress: list, done: list, llm) -> str:
    total = len(todo) + len(inprogress) + len(done)
    pct   = round(len(done) / total * 100) if total else 0

    assignee_done  = Counter(i["assignee"] for i in done)
    assignee_total = Counter(i["assignee"] for i in todo + inprogress + done)

    done_eng    = [i for i in done if not is_oncall(i)]
    done_oncall = [i for i in done if     is_oncall(i)]

    data = {
        "sprint":      sprint["name"],
        "period":      f"{sprint.get('startDate','')[:10]} → {sprint.get('endDate','')[:10]}",
        "completion":  f"{pct}% ({len(done)}/{total})",
        "by_assignee": {k: {"done": assignee_done[k], "total": assignee_total[k]}
                        for k in assignee_total},
        "done_engineering": [{"key": i["key"], "summary": i["summary"], "assignee": i["assignee"]}
                             for i in done_eng],
        "done_oncall_count": len(done_oncall),
        "in_progress": [{"key": i["key"], "summary": i["summary"], "assignee": i["assignee"]}
                        for i in inprogress],
        "todo":        [{"key": i["key"], "summary": i["summary"], "assignee": i["assignee"]}
                        for i in todo],
    }
    prompt = f"Sprint data:\n```json\n{json.dumps(data, indent=2)}\n```"
    return llm(
        [{"role": "user", "content": prompt}],
        system=_system(_SPRINT_ANALYSIS_SYSTEM),
        max_tokens=1024,
    )


# ---------------------------------------------------------------------------
# Jira helpers
# ---------------------------------------------------------------------------

def jira_get(path: str, token: str, params: dict = None) -> dict:
    resp = requests.get(
        f"{jira_base()}{path}",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        params=params or {},
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()


def get_active_sprint(board_id: int, token: str) -> dict:
    data    = jira_get(f"/rest/agile/1.0/board/{board_id}/sprint", token, {"state": "active"})
    sprints = data.get("values", [])
    if sprints:
        return sprints[0]
    # No active sprint — paginate all closed sprints, pick most recent by endDate
    all_closed, start = [], 0
    while True:
        page = jira_get(f"/rest/agile/1.0/board/{board_id}/sprint", token,
                        {"state": "closed", "maxResults": 50, "startAt": start})
        batch = page.get("values", [])
        all_closed.extend(batch)
        if page.get("isLast", True) or not batch:
            break
        start += len(batch)
    if not all_closed:
        raise RuntimeError(f"No active or closed sprint found for board {board_id}")
    most_recent = max(all_closed, key=lambda s: s.get("endDate", ""))
    print(f"No active sprint — using most recent closed sprint: {most_recent['name']}")
    return most_recent


def get_sprint_issues(sprint_id: int, token: str) -> list:
    issues, start = [], 0
    while True:
        data = jira_get(
            f"/rest/agile/1.0/sprint/{sprint_id}/issue",
            token,
            {"startAt": start, "maxResults": 100,
             "fields": "summary,status,assignee,priority,issuetype,resolutiondate,duedate"},
        )
        issues.extend(data.get("issues", []))
        if start + 100 >= data.get("total", 0):
            break
        start += 100
    return issues


def categorize(issues: list) -> tuple[list, list, list]:
    todo, inprogress, done = [], [], []
    for issue in issues:
        f   = issue["fields"]
        cat = f.get("status", {}).get("statusCategory", {}).get("name", "")
        item = {
            "key":       issue["key"],
            "summary":   f.get("summary", ""),
            "status":    f.get("status", {}).get("name", ""),
            "assignee":  (f.get("assignee") or {}).get("displayName", "Unassigned"),
            "priority":  (f.get("priority") or {}).get("name", ""),
            "issuetype": (f.get("issuetype") or {}).get("name", "Task"),
            "resolved":  (f.get("resolutiondate") or "")[:10],   # YYYY-MM-DD or ""
            "duedate":   (f.get("duedate") or "")[:10],          # YYYY-MM-DD or ""
        }
        if cat == "Done":
            done.append(item)
        elif cat == "In Progress":
            inprogress.append(item)
        else:
            todo.append(item)
    return todo, inprogress, done


def is_oncall(i: dict) -> bool:
    return i["summary"].upper().startswith(oncall_prefix().upper())


# ---------------------------------------------------------------------------
# Sprint Story — narrative business-facing summary
# ---------------------------------------------------------------------------

def _sprint_story(sprint: dict, todo: list, inprogress: list, done: list,
                  ai_narratives: dict = None, summary_note: str = "") -> list[str]:
    total    = len(todo) + len(inprogress) + len(done)
    pct      = round(len(done) / total * 100) if total else 0
    eng_done = [i for i in done       if not is_oncall(i)]
    oc_done  = [i for i in done       if     is_oncall(i)]
    eng_ip   = [i for i in inprogress if not is_oncall(i)]

    ai       = ai_narratives or {}
    story_md = ai.get("story_md", "")

    lines = ["## Sprint Story", ""]

    if story_md:
        # AI-generated full story body
        lines += story_md.splitlines()
        lines.append("")
    else:
        # Fallback: plain flat lists
        parts = []
        if eng_done:
            parts.append(f"{len(eng_done)} engineering item{'s' if len(eng_done)!=1 else ''}")
        if oc_done:
            parts.append(f"{len(oc_done)} oncall incident{'s' if len(oc_done)!=1 else ''} resolved")
        narrative = ", ".join(parts) if parts else "work items completed"
        lines += [
            f"> **{sprint['name']}** — {pct}% complete ({len(done)}/{total} items done)",
            ">",
            f"> The team delivered {narrative} this sprint"
            + (f", with {len(eng_ip)} item{'s' if len(eng_ip)!=1 else ''} still in progress" if eng_ip else "")
            + (f" and {len(todo)} remaining in the backlog" if todo else "") + ".",
            "",
        ]
        if eng_done:
            lines += [f"### Completed Engineering Work ({len(eng_done)} items)", ""]
            for i in eng_done:
                lines.append(f"- {i['summary']}")
            lines.append("")
        if eng_ip:
            lines += [f"### In Progress ({len(eng_ip)} items)", ""]
            for i in eng_ip:
                lines.append(f"- {i['summary']}  _{i['assignee']}_")
            lines.append("")
        if todo:
            lines += [f"### Not Started — At Risk ({len(todo)} items)", ""]
            for i in todo:
                lines.append(f"- {i['summary']}  _{i['assignee']}_")
            lines.append("")

    # ── Work Timeline — AI-bucketed by completion horizon ─────────────────────
    timeline_md = ai.get("timeline_md", "")
    if timeline_md:
        lines += ["---", "", "## Work Timeline", ""]
        lines += timeline_md.splitlines()
        lines.append("")

    # ── References — always from live Jira data ───────────────────────────────
    all_items = done + inprogress + todo
    if all_items:
        lines += [
            "### References",
            "",
            "| Key | Summary | Status | Assignee |",
            "|-----|---------|--------|----------|",
        ]
        for i in all_items:
            lines.append(
                f"| {link(i)} | {i['summary']} | {i['status']} | {i['assignee']} |"
            )
        lines.append("")

    return lines


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def link(i: dict) -> str:
    return f"[{i['key']}]({jira_base()}/browse/{i['key']})"


def render_sprint_detail(sprint: dict, board_id: int,
                         todo: list, inprogress: list, done: list,
                         ai_analysis: str = "", ai_narratives: dict = None,
                         summary_note: str = "") -> str:
    total = len(todo) + len(inprogress) + len(done)
    start = sprint.get("startDate", "")[:10]
    end   = sprint.get("endDate",   "")[:10]

    def todo_row(i):
        return f"| {link(i)} | {i['summary']} | {i['assignee']} | {i['priority']} |"

    def ip_row(i):
        return f"| {link(i)} | {i['summary']} | {i['status']} | {i['assignee']} | {i['priority']} |"

    def done_row(i):
        return f"| {link(i)} | {i['summary']} | {i['status']} | {i['assignee']} |"

    lines = [
        f"# Sprint: {sprint['name']}",
        f"**Board:** {board_id}  ",
        f"**Sprint ID:** {sprint['id']}  ",
        f"**Period:** {start} → {end}  ",
        f"**Total Issues:** {total}",
        "",
        "---",
        "",
    ]

    if ai_analysis:
        lines += ["## AI Analysis", "", ai_analysis, "", "---", ""]

    lines += [
        f"## TODO ({len(todo)})",
        "",
        "| Key | Summary | Assignee | Priority |",
        "|-----|---------|----------|----------|",
        *[todo_row(i) for i in todo],
        "",
        "---",
        "",
        f"## IN PROGRESS ({len(inprogress)})",
        "",
        "| Key | Summary | Status | Assignee | Priority |",
        "|-----|---------|--------|----------|----------|",
        *[ip_row(i) for i in inprogress],
        "",
        "---",
        "",
        f"## DONE ({len(done)})",
        "",
        "| Key | Summary | Status | Assignee |",
        "|-----|---------|--------|----------|",
        *[done_row(i) for i in done],
        "",
        "---",
        "",
        *_sprint_story(sprint, todo, inprogress, done, ai_narratives, summary_note),
    ]
    return "\n".join(lines)


def render_summary_concise(sprint: dict, board_id: int,
                           todo: list, inprogress: list, done: list,
                           ai_analysis: str = "", ai_narratives: dict = None,
                           summary_note: str = "") -> str:
    total = len(todo) + len(inprogress) + len(done)
    pct   = round(len(done) / total * 100) if total else 0
    start = sprint.get("startDate", "")[:10]
    end   = sprint.get("endDate",   "")[:10]

    done_eng    = [i for i in done if not is_oncall(i)]
    done_oncall = [i for i in done if     is_oncall(i)]

    done_lines = [f"- {i['summary']}" for i in done_eng]
    if done_oncall:
        done_lines.append(f"- Remaining {len(done_oncall)} items: oncall support requests (Resolved/Closed)")

    lines = [
        f"# Sprint Summary: {sprint['name']}",
        f"**Period:** {start} → {end}  ",
        f"**Board:** {board_id} | **Total Issues:** {total} | **Completion:** {pct}% ({len(done)}/{total})",
        "",
        "---",
        "",
    ]

    if ai_analysis:
        lines += ["## AI Analysis", "", ai_analysis, "", "---", ""]

    lines += [
        f"## Done ({len(done)})",
        "Key engineering items:",
        *done_lines,
        "",
        f"## In Progress ({len(inprogress)})",
        *[f"- {i['summary']}" for i in inprogress],
        "",
        f"## Todo ({len(todo)}) — At Risk",
        *[f"- {i['summary']}" for i in todo],
    ]

    lines += [
        "",
        "---",
        "",
        *_sprint_story(sprint, todo, inprogress, done, ai_narratives, summary_note),
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Jira sprint summary")
    parser.add_argument("--board",    type=int, help="Jira board ID (default: $JIRA_BOARD_ID)")
    parser.add_argument("--ai",       action="store_true", help="Add AI analysis via Claude")
    parser.add_argument("--save",     action="store_true", help="Save sprint detail and summary to markdown files")
    parser.add_argument("--env-file", help="Path to a .env file (default: ./.env if present)")
    args = parser.parse_args()

    env_file = Path(args.env_file) if args.env_file else Path(".env")
    load_config(env_file)

    board_id = args.board or (int(cfg("JIRA_BOARD_ID")) if cfg("JIRA_BOARD_ID") else None)
    if not board_id:
        parser.error("board ID required: pass --board or set JIRA_BOARD_ID")
    token = require("JIRA_TOKEN")

    print(f"Fetching active sprint for board {board_id}...")
    sprint = get_active_sprint(board_id, token)
    print(f"Sprint: {sprint['name']} (ID: {sprint['id']})")

    print("Fetching issues...")
    issues = get_sprint_issues(sprint["id"], token)
    todo, inprogress, done = categorize(issues)

    ai_analysis   = ""
    ai_narratives = {}
    summary_note  = ""
    if args.ai:
        print("Running AI analysis...")
        try:
            llm = get_llm()
            ai_analysis = ai_analyze_sprint(sprint, todo, inprogress, done, llm)
            print("  AI analysis complete.")
            print("  Generating sprint story narratives...")
            ai_narratives = ai_story_narrative(done, inprogress, todo, llm)
            print("  Story narratives complete.")
            print("  Generating work timeline...")
            ai_narratives["timeline_md"] = ai_timeline_narrative(
                sprint, done, inprogress, todo, llm)
            print("  Work timeline complete.")
            print("  Generating summary note...")
            summary_note = generate_summary_note(done, inprogress, todo, llm)
            print("  Summary note complete.")
        except Exception as exc:
            print(f"  Warning: AI analysis failed — {exc}")

    summary = render_summary_concise(sprint, board_id, todo, inprogress, done,
                                     ai_analysis=ai_analysis, ai_narratives=ai_narratives,
                                     summary_note=summary_note)
    print("\n" + summary)

    if args.save:
        out_dir      = Path(__file__).parent
        ai_tag       = "_ai" if args.ai else ""
        sprint_file  = out_dir / f"sprint_{sprint['name']}{ai_tag}.md"
        summary_file = out_dir / f"summary_{sprint['name']}{ai_tag}.md"

        sprint_file.write_text(
            render_sprint_detail(sprint, board_id, todo, inprogress, done,
                                 ai_analysis=ai_analysis, ai_narratives=ai_narratives,
                                 summary_note=summary_note)
        )
        summary_file.write_text(summary)

        print(f"\nSaved to {sprint_file}")
        print(f"Saved to {summary_file}")


if __name__ == "__main__":
    main()
