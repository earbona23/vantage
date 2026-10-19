# Security policy

## Reporting a vulnerability

Open a [private security advisory](https://github.com/earbona23/vantage/security/advisories/new)
on this repository, or email **earbona@arrankago.com**. Please do not open a public issue
for a vulnerability.

You will get an acknowledgement within 72 hours and an assessment within seven days. There
is no bounty programme — this is a single-maintainer project — but every report is credited
unless you ask me not to.

## What counts as a vulnerability here

vantage reads public DNS, TLS and HTTP signals for a domain you point it at. In scope:

- **A request to an internal destination.** Any input that makes vantage connect to a
  private, loopback, link-local or otherwise internal address (SSRF), including through
  redirects or alternative IP notations.
- **Anything beyond passive reads.** A probe, write or exploit attempt against the target.
- **Injection into the report.** Attacker-controlled content from a target reaching the
  rendered output unescaped.
- **A weak posture reported as strong.** A failed or incomplete check presented as a pass.

Out of scope: a score you would weigh differently — open a normal issue.
