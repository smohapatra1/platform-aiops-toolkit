#!/usr/bin/env python3
"""
Fetch and summarize the active Jira sprint for a given board.

Outputs a markdown sprint report: todo / in-progress / done breakdown,
with a concise summary that separates engineering work from support tickets.

Usage:
    python3 jira_sprint_summary.py [--board 1234] [--save]

Environment variables (or .env file):
    JIRA_BASE_URL   Base URL of your Jira instance (e.g. https://jira.your-company.com)
    JIRA_TOKEN      Personal access token with read access to the board
    JIRA_BOARD_ID   Default board ID (overridden by --board flag)
"""

import argparse
import os
import sys
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

try:
    import requests
except ImportError:
    print("Missing dependency: pip install requests")
    sys.exit(1)

JIRA_BASE = os.environ.get("JIRA_BASE_URL", "https://jira.your-company.com")
DEFAULT_BOARD = int(os.environ.get("JIRA_BOARD_ID", "0"))


def load_token() -> str:
    token = os.environ.get("JIRA_TOKEN", "")
    if not token:
        print("ERROR: JIRA_TOKEN not set. Add it to your .env file or environment.")
        sys.exit(1)
    return token


def jira_get(path: str, token: str, params: dict = None) -> dict:
    url = f"{JIRA_BASE}{path}"
    resp = requests.get(
        url,
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        params=params or {},
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()


def get_active_sprint(board_id: int, token: str) -> dict:
    data = jira_get(f"/rest/agile/1.0/board/{board_id}/sprint", token, {"state": "active"})
    sprints = data.get("values", [])
    if not sprints:
        raise RuntimeError(f"No active sprint found for board {board_id}")
    return sprints[0]


def get_sprint_issues(sprint_id: int, token: str) -> list:
    issues, start = [], 0
    while True:
        data = jira_get(
            f"/rest/agile/1.0/sprint/{sprint_id}/issue",
            token,
            {"startAt": start, "maxResults": 100,
             "fields": "summary,status,assignee,priority,issuetype"},
        )
        issues.extend(data.get("issues", []))
        if start + 100 >= data.get("total", 0):
            break
        start += 100
    return issues


def categorize(issues: list) -> tuple[list, list, list]:
    todo, inprogress, done = [], [], []
    for issue in issues:
        f = issue["fields"]
        cat = f.get("status", {}).get("statusCategory", {}).get("name", "")
        item = {
            "key": issue["key"],
            "summary": f.get("summary", ""),
            "status": f.get("status", {}).get("name", ""),
            "assignee": (f.get("assignee") or {}).get("displayName", "Unassigned"),
            "priority": (f.get("priority") or {}).get("name", ""),
        }
        if cat == "Done":
            done.append(item)
        elif cat == "In Progress":
            inprogress.append(item)
        else:
            todo.append(item)
    return todo, inprogress, done


def is_support_ticket(i: dict) -> bool:
    """Identify support/oncall tickets by summary prefix convention."""
    return i["summary"].upper().startswith("[ONCALL]") or i["summary"].upper().startswith("[SUPPORT]")


def render_sprint_detail(sprint: dict, board_id: int, todo: list, inprogress: list, done: list) -> str:
    total = len(todo) + len(inprogress) + len(done)
    start = sprint.get("startDate", "")[:10]
    end   = sprint.get("endDate",   "")[:10]

    def link(i):
        return f"[{i['key']}]({JIRA_BASE}/browse/{i['key']})"

    lines = [
        f"# Sprint: {sprint['name']}",
        f"**Board:** {board_id}  ",
        f"**Sprint ID:** {sprint['id']}  ",
        f"**Period:** {start} → {end}  ",
        f"**Total Issues:** {total}",
        "",
        "---",
        "",
        f"## TODO ({len(todo)})",
        "",
        "| Key | Summary | Assignee | Priority |",
        "|-----|---------|----------|----------|",
        *[f"| {link(i)} | {i['summary']} | {i['assignee']} | {i['priority']} |" for i in todo],
        "",
        "---",
        "",
        f"## IN PROGRESS ({len(inprogress)})",
        "",
        "| Key | Summary | Status | Assignee | Priority |",
        "|-----|---------|--------|----------|----------|",
        *[f"| {link(i)} | {i['summary']} | {i['status']} | {i['assignee']} | {i['priority']} |" for i in inprogress],
        "",
        "---",
        "",
        f"## DONE ({len(done)})",
        "",
        "| Key | Summary | Status | Assignee |",
        "|-----|---------|--------|----------|",
        *[f"| {link(i)} | {i['summary']} | {i['status']} | {i['assignee']} |" for i in done],
    ]
    return "\n".join(lines)


def render_summary_concise(sprint: dict, todo: list, inprogress: list, done: list) -> str:
    total = len(todo) + len(inprogress) + len(done)
    pct   = round(len(done) / total * 100) if total else 0
    start = sprint.get("startDate", "")[:10]
    end   = sprint.get("endDate",   "")[:10]

    done_eng     = [i for i in done if not is_support_ticket(i)]
    done_support = [i for i in done if     is_support_ticket(i)]

    done_lines = [f"- {i['summary']}" for i in done_eng]
    if done_support:
        done_lines.append(f"- Remaining {len(done_support)} item(s): oncall/support requests (Resolved/Closed)")

    lines = [
        f"# Sprint Summary: {sprint['name']}",
        f"**Period:** {start} → {end}  ",
        f"**Total Issues:** {total} | **Completion:** {pct}% ({len(done)}/{total})",
        "",
        "---",
        "",
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
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Jira sprint summary")
    parser.add_argument("--board", type=int, default=DEFAULT_BOARD, help="Jira board ID")
    parser.add_argument("--save", action="store_true", help="Save sprint detail and summary to markdown files")
    args = parser.parse_args()

    if not args.board:
        print("ERROR: Provide --board or set JIRA_BOARD_ID in your environment.")
        sys.exit(1)

    token = load_token()

    print(f"Fetching active sprint for board {args.board}...")
    sprint = get_active_sprint(args.board, token)
    print(f"Sprint: {sprint['name']} (ID: {sprint['id']})")

    print("Fetching issues...")
    issues = get_sprint_issues(sprint["id"], token)
    todo, inprogress, done = categorize(issues)

    summary = render_summary_concise(sprint, todo, inprogress, done)
    print("\n" + summary)

    if args.save:
        out_dir = Path(__file__).parent
        sprint_file  = out_dir / f"sprint_{sprint['name']}.md"
        summary_file = out_dir / f"summary_{sprint['name']}.md"
        sprint_file.write_text(render_sprint_detail(sprint, args.board, todo, inprogress, done))
        summary_file.write_text(summary)
        print(f"\nSaved: {sprint_file}")
        print(f"Saved: {summary_file}")


if __name__ == "__main__":
    main()
