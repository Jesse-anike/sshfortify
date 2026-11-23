# SSH FORTIFY — SSHD Configuration Hardening Auditor

A read-only Python auditor that reviews an OpenSSH `sshd_config` file against a practical defensive baseline. It reports risky or missing global directives and notes configuration features requiring additional review.

## Baseline checks

- `PermitRootLogin no`
- `PasswordAuthentication no`
- `KbdInteractiveAuthentication no`
- `X11Forwarding no`
- `MaxAuthTries 4` or a lower value

The parser respects the first global occurrence of a directive and does not mistake directives inside `Match` blocks for global settings. It reports `Include` directives and `Match` blocks for manual follow-up; it does not recursively resolve include files.

## Requirements

- Python 3.10+
- Python standard library only

## Run

```bash
python main.py sample.log
```

Read a config from standard input:
```bash
cat /etc/ssh/sshd_config | python main.py -
```

Save a JSON report:
```bash
python main.py /etc/ssh/sshd_config --output ssh-audit.json
```

For a complete effective-configuration review, also run `sshd -T` using an authorized administrative workflow and inspect the output. SSH settings can vary by OpenSSH version, included files, command-line options, and `Match` conditions. This project is a lightweight file review, not a replacement for validating the effective daemon configuration.

## Tests

```bash
python -m unittest discover -s tests -v
python main.py --help
```

## Safety

The auditor reads configuration text only. It does not restart SSH, edit files, change firewall rules, or lock out administrators. Test changes in a controlled environment and maintain an authorized recovery path before applying hardening recommendations.

## Portfolio context

Built for Anike-Moses Melie Jesse's defensive cybersecurity and cloud-security portfolio, demonstrating Linux service hardening, configuration parsing, secure administration principles, Python automation, and actionable reporting.
