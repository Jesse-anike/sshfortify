from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


BASELINE = {
    "permitrootlogin": ("no", "Disable direct SSH login as root."),
    "passwordauthentication": ("no", "Prefer key-based authentication where supported by the access policy."),
    "kbdinteractiveauthentication": ("no", "Disable keyboard-interactive authentication unless explicitly required."),
    "x11forwarding": ("no", "Disable X11 forwarding when it is not required."),
    "maxauthtries": ("4", "Limit authentication attempts per connection."),
}


def parse_global_settings(text: str) -> dict:
    settings = {}
    includes = []
    match_blocks = []
    in_match = False

    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue

        parts = line.split(None, 1)
        key = parts[0].lower()
        value = parts[1].strip() if len(parts) > 1 else ""

        if key == "match":
            in_match = True
            match_blocks.append({"line": line_number, "condition": value})
            continue

        if in_match:
            # sshd_config Match blocks continue until end of file; they do not
            # become global again later in the same file.
            continue

        if key == "include":
            includes.append({"line": line_number, "pattern": value})
            continue

        # OpenSSH generally uses the first obtained value for most scalar
        # directives. Retain the first global occurrence.
        if key not in settings and value:
            settings[key] = {"value": value.lower(), "line": line_number}

    return {
        "settings": settings,
        "includes": includes,
        "match_blocks": match_blocks,
    }


def analyze(text: str) -> dict:
    parsed = parse_global_settings(text)
    settings = parsed["settings"]
    findings = []

    for directive, (expected, reason) in BASELINE.items():
        entry = settings.get(directive)
        observed = entry["value"] if entry else None

        if directive == "maxauthtries" and observed is not None:
            try:
                compliant = int(observed) <= int(expected)
            except ValueError:
                compliant = False
        else:
            compliant = observed == expected

        if not compliant:
            findings.append({
                "setting": directive,
                "observed": observed if observed is not None else "(not explicitly set)",
                "recommended": expected,
                "reason": reason,
                "line": entry["line"] if entry else None,
            })

    return {
        "settings_reviewed": len(BASELINE),
        "global_settings_found": len(settings),
        "findings": findings,
        "finding_count": len(findings),
        "include_directives": parsed["includes"],
        "match_blocks": parsed["match_blocks"],
        "manual_review_required": bool(parsed["includes"] or parsed["match_blocks"]),
        "notes": [
            "This tool reviews the supplied file only; it does not resolve Include files.",
            "Match blocks are reported but not evaluated against individual users or hosts.",
            "Confirm effective settings with an authorized sshd -T check before applying changes.",
            "No configuration, service, account, or firewall changes are made.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit OpenSSH sshd_config global directives against a defensive baseline."
    )
    parser.add_argument("target", nargs="?", default="-", help="Path to sshd_config; use - or omit to read stdin.")
    parser.add_argument("--output", help="Optional JSON report output path.")
    args = parser.parse_args()

    try:
        raw = (
            sys.stdin.read()
            if args.target == "-"
            else Path(args.target).read_text(encoding="utf-8", errors="replace")
        )
    except OSError as exc:
        print(json.dumps({"error": str(exc)}, indent=2), file=sys.stderr)
        return 2

    report = analyze(raw)
    rendered = json.dumps(report, indent=2)
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
