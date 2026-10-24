# vantage

> **Maintained.** One of the four tools here I keep current: bug fixes, dependency and
> rule-catalogue updates, and issues answered. The rest of my tools are published as
> snapshots and say so at the top of their README.

> 🔎 **Try this and the whole suite online — no install:** [consulting.arrankago.com](https://consulting.arrankago.com) · plus managed security and M365/Entra identity assessments for teams.

[![CI](https://github.com/earbona23/vantage/actions/workflows/ci.yml/badge.svg)](https://github.com/earbona23/vantage/actions/workflows/ci.yml)
[![Node 18.18+](https://img.shields.io/badge/Node-18.18%2B-339933)](https://nodejs.org/)
[![Licence: MIT](https://img.shields.io/badge/Licence-MIT-blue.svg)](LICENSE)
[![Runtime dependencies: 0](https://img.shields.io/badge/runtime%20deps-0-2f855a)](#zero-dependencies-is-a-security-property)
[![Mutation tested](https://img.shields.io/badge/mutation-17%2F17%20killed-2f855a)](#mutation-testing-break-it-on-purpose)

**A transparent external security-posture scorer for a domain.** Point it at a
domain and it produces a scored, explainable report of the domain's *public*
posture — email authentication, DNS hygiene, transport security, web headers,
and dangling-CNAME takeover exposure. Every point in the score traces back to a
named rule you can read and argue with.

```console
$ vantage scan github.com
```

```
vantage report — github.com

Verdict: B  (good, with gaps)
Posture score: 76 / 100
[###############.....] 76/100

Checks evaluated: 13   not evaluable: 0   points: 74/97
Findings — critical:0 high:0 medium:2 low:3 info:1

Findings (each one is a rule you can argue with):
  [MEDIUM] mtasts.missing  (mtasts)
      No MTA-STS record. Sending servers cannot know to require TLS for mail...
  [MEDIUM] dnssec.unsigned  (dnssec)
      DNSSEC is not enabled. DNS answers for this domain are not signed...
  [LOW] dmarc.policy_quarantine  (dmarc)
      DMARC policy is quarantine. Failing mail is sent to spam rather than rejected...
```

## What it is, and what it is not

This is a **transparent scorer**, not a black box. It is the opposite of the
"threat intelligence score" you cannot inspect.

- It reads **only public data**: DNS records, the TLS handshake on 443, and the
  HTTP response headers on the front page. That is data anyone can query.
- It does **not** exploit anything, does **not** port-scan, does **not** brute
  force, and does **not** touch any private or proprietary feed. There is no
  SOCRadar-style dataset behind it, because that is the point: I would rather
  ship a number you can reconstruct by hand than a number you have to trust.
- **The score is not a probability of being breached.** It is N assertions,
  each with a rule id, a severity, and a remediation. If you disagree with one,
  you can point at exactly which rule and why. A scorecard you can't audit is
  just a vibe with a decimal point.

It reads the same signals a competent attacker checks first when they decide
whether your domain is worth their afternoon.

## The three states, and why they matter

Every check reports one of three things, never two:

- **finding** — I looked, and here is something worth fixing.
- **clean** — I looked, and it is fine.
- **not evaluable** — I could **not** look (the domain didn't resolve, the site
  timed out, there is no MX so mail-transport checks don't apply).

"I could not look" is **never** folded into "clean". A domain that fails to
resolve does not get a free pass on SPF — it gets a report that says, plainly,
that SPF could not be evaluated. **Not-evaluable checks are excluded from the
score entirely** — they never inflate it and never drag it down. If nothing at
all could be evaluated, the score is `null`, not `0` and not `100`. A tool that
turns "I didn't check" into "looks good" is worse than no tool.

## Install

Zero dependencies, so there is nothing to install but Node.

```console
$ git clone https://github.com/earbona23/vantage.git
$ cd vantage
$ node src/index.js scan example.com
# or link it as a bin:
$ npm link && vantage scan example.com
```

Requires Node 18.18+. Note that this tool is **not published to npm**: the package
named `vantage` in the registry is an unrelated project by another author, so do not
`npm install vantage` expecting this. Clone it, as above.

No `npm install` step, because there is nothing to
install.

## Usage

```console
$ vantage scan <domain> [--format terminal|json|sarif|md] [--subdomains a,b] [--color]
$ vantage batch <file>  [--format json|jsonl]                       # PRO
$ vantage diff <domain> --snapshot <file> [--save <file>]           # PRO
$ vantage version
$ vantage help
```

Output formats:

| Format     | Use it for |
|------------|------------|
| `terminal` | reading it yourself (default) |
| `json`     | a stable machine contract (`schema`, `score`, `verdict`, `summary`, `checks`, `findings`) |
| `sarif`    | uploading to a code-scanning dashboard (SARIF 2.1.0) |
| `md`       | pasting into a PR or an issue |

As a CI gate, `scan` exits non-zero when there is a **critical** finding (for
example a confirmed dangling-CNAME takeover), and `0` otherwise. Not-evaluable
alone never fails your build.

## What it checks

**Email authentication**
- **SPF** — present, exactly one record, and the `all` qualifier (`+all` is
  flagged as *worse* than no SPF, because it authorises the whole internet).
- **DKIM** — probes common selectors. A miss is reported as *inconclusive*, not
  as a failure, because you may sign with a selector this scan doesn't know.
- **DMARC** — present, and how strict: `none` / `quarantine` / `reject`, plus
  `rua`, `pct`, `sp`.
- **BIMI** — informational only; its absence is never a security finding.

**Transport (only when the domain has an MX)**
- **MX** present; **MTA-STS** record *and* a reachable policy in `enforce` mode;
  **TLS-RPT** reporting.

**DNS**
- **DNSSEC** — via a validating resolver's authenticated-data flag and a DS
  record at the parent.
- **CAA** — restricts which CAs may issue, including a wildcard policy.

**Web**
- **TLS** — chain validity, expiry proximity, obsolete protocol floor.
- **Security headers** — HSTS (and its strength), CSP, clickjacking protection
  (X-Frame-Options *or* CSP `frame-ancestors`), `nosniff`, Referrer-Policy,
  Permissions-Policy. Version disclosure is noted as info only.
- **security.txt** (RFC 9116) — present, has a Contact, and not expired.

**Exposure**
- **Subdomain takeover** — for each probed subdomain, a dangling CNAME to an
  unclaimed hosting service, matched by known fingerprints. A confirmed one is
  the only thing that zeroes its check outright.

## The score

Each evaluable check contributes `earned / weight` points; the score is
`round(100 * Σearned / Σweight)` over the evaluable checks. The verdict bands:

| Grade | Score  | Meaning |
|:-----:|:------:|---------|
| **A** | 90–100 | strong public posture |
| **B** | 75–89  | good, with gaps |
| **C** | 60–74  | mixed |
| **D** | 40–59  | weak |
| **F** | 0–39   | poor public posture |

The `--format json` and `--format md` outputs both print a per-check ledger, so
you can see exactly which points each check earned or lost.

## Free vs PRO

The **core that decides the score is free and MIT-licensed**, forever. PRO does
not change a single verdict — it adds *reach*:

| | Free (MIT) | PRO |
|---|---|---|
| Single-domain scan | ✅ | ✅ |
| All the checks & the full score | ✅ | ✅ |
| terminal / json / sarif / md | ✅ | ✅ |
| Portfolio batch scanning | | ✅ |
| Monitoring **diff** (what changed since the last snapshot) | | ✅ |
| JSONL / HTML output | | ✅ |

PRO is unlocked with an **offline licence key** — an Ed25519-signed token
verified entirely on your machine. There is no licence server, no phone-home,
no network call of any kind to check it. Supply it with `--license` or the
`VANTAGE_LICENSE` environment variable. If the key is missing, expired, or
tampered, the PRO command refuses — it never silently downgrades to something
that looks like it worked.

## Zero dependencies is a security property

vantage imports nothing but the Node standard library — `node:dns`, `node:tls`,
`node:https`, `node:crypto`. There is no `dependencies` block, no `npm install`,
no transitive tree to audit, and no supply-chain surface for a tool whose whole
job is to reduce your attack surface.

This is not an aspiration in the README — it is **enforced by a test** that
fails if `package.json` ever grows a dependency or if any source file imports a
third-party package. If that property is ever lost, CI goes red.

## Mutation testing: break it on purpose

A green test suite proves the tests ran, not that they would notice a bug. So
the suite is checked by a mutation harness (`npm run mutation`) that injects
**real defects** one at a time — downgrade a severity, move a verdict boundary,
fold "not evaluable" back into the score, break a takeover fingerprint, bypass
the licence signature check — and confirms a test turns red for each. A defect
the suite sleeps through is a *survivor*, and a survivor fails the harness.

```console
$ npm run mutation
baseline: running suite... green

killed    SPF +all no longer zeroed (critical downgraded)
killed    not_evaluable folded into the score denominator
killed    score returns 0 instead of null when nothing is evaluable
killed    licence signature check bypassed
...
mutation score: 17/17 killed
all mutants killed.
```

## Development

```console
$ npm test          # node --test, offline and deterministic
$ npm run mutation  # inject defects; every one must be caught
```

Tests never touch the network. The one module that does — the collector — is
driven in tests by injected fake DNS/HTTP/TLS clients backed by recorded
fixtures. Every check is a pure function of a recorded evidence object, which is
why they are trivial to test and hard to fool.

## Sponsor

vantage is MIT and free forever. If it catches an exposure before an attacker does,
or earns a place in your pipeline, sponsoring keeps it maintained: bug fixes, keeping
the takeover fingerprints and rule catalogue current, and testing against new behaviour.

- **[Sponsor on GitHub](https://github.com/sponsors/earbona23)** — any amount.
- **PRO licences** — batch scanning, monitoring diffs and JSONL/HTML export, per
  organisation with unlimited users in the seat band: **US$29/mo** Solo, US$99 Team (≤10),
  US$299 Business (≤50), annual at two months free.
  **[Buy at consulting.arrankago.com](https://consulting.arrankago.com)** or email
  earbona@arrankago.com. Those are the figures charged on that site, which is where they are
  maintained.
- **Investigations** — a domain or portfolio deep-dive with a prioritised report, from US$6,500 per investigation. Email earbona@arrankago.com.

## More tools like this

Part of a small suite of dependency-free security tools I maintain. Each one runs
offline, ships its own tests, and maps its findings to a rule you can argue with.

- **[entraform](https://github.com/earbona23/entraform)** — catch risky Entra/Azure changes in a Terraform plan, before apply.
- **[revtriage](https://github.com/earbona23/revtriage)** — offline malware triage: an explainable score and a STIX bundle from a suspicious file.
- **[entra-tripwire](https://github.com/earbona23/entra-tripwire)** — decoy identities in Entra ID that fire the moment someone touches them.
- **[containment-cut](https://github.com/earbona23/containment-cut)** — the minimum-cost set of actions that provably severs a compromised identity, with a proof.

## Licence

MIT. See [LICENSE](LICENSE).
