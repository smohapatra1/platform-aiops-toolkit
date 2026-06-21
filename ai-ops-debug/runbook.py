"""
Generate a structured AI runbook from collected debug output using Claude API.

Requires: pip install anthropic
Environment: ANTHROPIC_API_KEY
"""

import os


SYSTEM_PROMPT = """You are a senior platform/cloud engineer specializing in compute node operations,
Linux networking (OVS, GRE/VXLAN tunnels, DPDK), and distributed infrastructure.

When given debug output and findings from a compute node, produce a structured runbook with:
1. Executive Summary — state of the host in one paragraph
2. Findings — bullet list with severity (ERROR/WARNING/INFO) and operational impact
3. Root Cause Analysis — most likely cause(s) based on the evidence
4. Remediation Steps — numbered, actionable steps an on-call engineer can follow right now
5. Verification Commands — commands to confirm the fix worked
6. Escalation — when to escalate and to whom

Be concise and technical. Use exact command output snippets where relevant. Avoid generic advice."""


def build_prompt(host, playbook_name, results, findings):
    sections = []
    for r in results:
        block = "[{label}] $ {cmd}\n{stdout}".format(
            label=r["label"],
            cmd=r["cmd"],
            stdout=r["stdout"].strip() or "(no output)",
        )
        if r["stderr"]:
            block += "\nSTDERR: " + r["stderr"]
        sections.append(block)

    if findings:
        lines = []
        for f in findings:
            lines.append("[{severity}] {message} (pattern: {pattern}, section: {label})".format(**f))
            if f.get("matched_text"):
                lines.append("  matched: {matched_text}".format(**f))
        findings_text = "\n".join(lines)
    else:
        findings_text = "No automated patterns fired."

    return """Host: {host}
Playbook: {playbook}

=== AUTO-DETECTED FINDINGS ===
{findings}

=== COLLECTED OUTPUT ===
{output}

Generate a runbook for an on-call engineer.""".format(
        host=host,
        playbook=playbook_name,
        findings=findings_text,
        output="\n\n".join(sections),
    )


def generate(host, playbook_name, results, findings) -> str:
    """Call Claude API to generate a runbook. Returns the runbook as a string."""
    try:
        import anthropic
    except ImportError:
        raise ImportError("anthropic package required: pip install anthropic")

    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY not set in environment")

    client = anthropic.Anthropic(api_key=api_key)
    prompt = build_prompt(host, playbook_name, results, findings)

    message = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=2048,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": prompt}],
    )
    return message.content[0].text
