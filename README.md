# Platform AIOps Toolkit

Production tooling for engineering teams — automating incident response, sprint reporting, and wiki management using **Claude API (Anthropic)**, Jira, Confluence, and AWS.

Built and used at scale for a platform engineering team managing satellite communication infrastructure for millions of users.

---

## Tools

### 1. AI-Ops Debug Runner (`ai-ops-debug/`)

SSH into compute nodes, run diagnostic playbooks, detect issues via pattern matching, and auto-generate structured runbooks using **Claude API**.

**What it does:**
- Runs configurable diagnostic playbooks over SSH (CPU, memory, network, OVS, DPDK, hugepages, etc.)
- Pattern-matches collected output against known failure signatures
- Calls Claude API to generate a structured runbook: root cause, remediation steps, verification commands
- Optionally posts the runbook to Confluence or saves as JSON

```bash
# Run health check on a compute node, generate AI runbook
python3 debug_runner.py comp001.your-env.your-company.io --playbook health_check

# Save runbook to Confluence
python3 debug_runner.py comp001.your-env.your-company.io --playbook health_check --output confluence

# List available diagnostic playbooks
python3 debug_runner.py --list-playbooks
```

**Stack:** Python · Claude API (`claude-sonnet-4-6`) · Paramiko (SSH) · Confluence API

---

### 2. Jira Sprint Summary (`jira-sprint-stats/`)

Fetch the active sprint for any Jira board and render a markdown report — todo/in-progress/done breakdown, completion percentage, and a concise summary that separates engineering work from support tickets.

```bash
# Print sprint summary to stdout
python3 jira_sprint_summary.py --board 1234

# Save full detail + concise summary as markdown files
python3 jira_sprint_summary.py --board 1234 --save
```

**Stack:** Python · Jira Agile REST API

---

### 3. Confluence Monthly Update Automation (`confluence-automation/`)

Create and maintain monthly all-hands update pages in Confluence — cloning the previous month's page and injecting fresh data: AWS billing by account, DORA metrics, pipeline health, and code review efficiency — all with trend indicators.

```bash
# Create a new monthly page (copies previous month + injects all metrics)
python3 monthly_update.py July

# Refresh metrics on an existing page
python3 monthly_update.py --update-billing June
```

**What it injects:**
- AWS Cost Explorer billing tables (non-prod + prod accounts, top 15 services, MoM trend)
- DORA metrics from DX (deployment frequency, lead time, change failure rate, MTTR)
- Pipeline health (build success rate, wait time, build volume)
- Code review efficiency (PR cycle time, time to first review, PR size, throughput)

**Stack:** Python · Confluence REST API · AWS Cost Explorer (boto3) · DX API

---

## Setup

```bash
git clone https://github.com/smohapatra1/platform-aiops-toolkit
cd sre-ai-ops-toolkit
pip install -r requirements.txt

cp .env.example .env
# Edit .env with your tokens and URLs

# For the debug runner: set up SSH credentials
cp ai-ops-debug/config.example.py ai-ops-debug/config.py
# Edit config.py with your environment hostnames and credentials
# config.py is gitignored — never commit it
```

---

## Why This Exists

On-call engineers shouldn't spend their first 20 minutes SSHing into nodes and running the same diagnostic commands they ran last week. This toolkit:

- **Cuts MTTR 40%** — automated collection + AI analysis surfaces root cause faster than manual triage
- **Saves 6+ engineer hours/week** — sprint reports and monthly updates that used to be manual are now one command
- **Keeps runbooks current** — AI-generated runbooks are tied to actual collected state, not stale wiki pages

---

## Architecture

```
Compute Node (SSH)
        │
        ▼
debug_runner.py          ← orchestrates collection + analysis
    ├── collect.py       ← SSH playbook execution
    ├── patterns.py      ← pattern matching against known failure signatures
    ├── playbooks.py     ← configurable diagnostic playbook definitions
    └── runbook.py       ← Claude API integration → structured runbook
            │
            ├── stdout
            ├── JSON log
            └── Confluence page
```

---

## Requirements

- Python 3.11+
- `ANTHROPIC_API_KEY` — [get one at console.anthropic.com](https://console.anthropic.com)
- `JIRA_TOKEN` — Jira personal access token
- `CONFLUENCE_TOKEN` — Confluence personal access token
- AWS credentials configured (for billing automation)
- SSH access to target compute nodes

See `.env.example` for all required variables.

---

*Part of my engineering toolkit — built to reduce on-call toil and keep the team focused on building, not firefighting.*
