# THREAT_MODEL.md schema

Both `/threat-model bootstrap` and `/threat-model interview` write this file to
`<target-dir>/THREAT_MODEL.md`. The format is markdown so humans can read and
edit it, but the section headings, table columns, and enum values below are a
contract: keep the headings and column order exactly as shown so downstream
tooling (`/vuln-scan`, `/vuln-triage`) can parse them with regex.

---

## Required sections, in order

```markdown
# Threat Model: <system name>

## 1. System context

## 2. Assets

## 3. Entry points & trust boundaries

## 4. Threats

## 5. Deprioritized

## 6. Open questions

## 7. Provenance

## 8. Recommended mitigations
```

A consumer that only needs the threat table can regex for `^## 4\. Threats$`
and read until the next `^## `. Section 8 is optional and additive.

---

## Section contents

### 1. System context

One to three paragraphs of prose: what the system is, what it does, who uses
it, where it runs. No table.

### 2. Assets

Markdown table. One row per thing worth protecting.

| asset | description | sensitivity |
|---|---|---|

`sensitivity` ∈ {`low`, `medium`, `high`, `critical`}.

### 3. Entry points & trust boundaries

Markdown table. One row per place untrusted input enters the system or
privilege level changes.

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|

`trust_boundary` is free text naming the crossing (e.g. "unauth HTTP →
application logic", "authenticated session → another user's data", "Worker →
upstream DNS/HTTP fetch").
`reachable_assets` is a comma-separated list of asset names from section 2.

### 4. Threats

Markdown table. **This is the threat model proper.** One row per
actor-wants-outcome pair, at the abstraction level where it survives a patch.

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|

- `id`: `T1`, `T2`, … Stable across edits; do not renumber when rows are
  removed.
- `threat`: one sentence, active voice, names the outcome. "Cross-tenant scan
  history disclosure via missing ownership check", not "missing user_id in
  scans.ts query".
- `actor` ∈ {`remote_unauth`, `remote_auth`, `adjacent_network`,
  `local_user`, `local_admin`, `supply_chain`, `insider`}.
- `surface`: which entry point(s) from section 3 this threat traverses.
- `asset`: which asset(s) from section 2 this threat compromises.
- `impact` ∈ {`low`, `medium`, `high`, `critical`, `existential`}.
- `likelihood` ∈ {`very_rare`, `rare`, `possible`, `likely`, `almost_certain`}.
- `status` ∈ {`unmitigated`, `partially_mitigated`, `mitigated`, `risk_accepted`}.
- `controls`: current mitigations, or `none`.
- `evidence`: CVE/GHSA IDs, issue links, pentest finding IDs, or git commit
  hashes that **instantiate** this threat. May be empty. **Evidence raises
  likelihood; it is not the threat.**

Sort by (impact, likelihood) descending so the top rows are the priorities.

### 5. Deprioritized

| threat | reason |
|---|---|

Common reasons: out of scope, actor not in threat model, asset not present,
risk accepted by owner.

### 6. Open questions

Bullet list. For `bootstrap`, questions for a human owner; for `interview`,
owner claims not verifiable in code.

### 7. Provenance

```markdown
- mode: interview | bootstrap | bootstrap-then-interview
- date: YYYY-MM-DD
- target: <path or repo url @ commit>
- inputs: <design doc path | --vulns path | "git-log + advisories mined">
- owner: <name, for interview> | <unset, for bootstrap>
```

### 8. Recommended mitigations

Optional, additive. Each row is **one class-level control**, not a per-finding
patch: a mitigation that closes or materially shrinks an entire threat cluster
regardless of which instance is found next.

```markdown
| mitigation | threat_ids | closes_class | effort |
|---|---|---|---|
```

- `mitigation`: imperative, one line (e.g., "centralize per-user row scoping in
  a query helper", "verify every inbound webhook signature before parsing",
  "escape all user input in HTML via esc() — never inline into <script>").
- `threat_ids`: comma-separated section-4 ids (e.g., `T1,T3`).
- `closes_class`: `yes` | `partial`.
- `effort`: `S` | `M` | `L`.

---

## Scoring guide

### Impact

| value | means |
|---|---|
| `low` | Nuisance; no data or availability loss. |
| `medium` | Limited data exposure or degraded availability for some users. |
| `high` | Significant data exposure, integrity loss, or full availability loss. |
| `critical` | Full compromise of a primary asset (RCE, auth bypass, data exfil at scale). |
| `existential` | Compromise threatens the organization's continued operation. |

### Likelihood

| value | means |
|---|---|
| `very_rare` | Requires nation-state resources or an unlikely chain of preconditions. |
| `rare` | Requires significant skill and a non-default configuration. |
| `possible` | A motivated attacker with public tooling could plausibly do this. |
| `likely` | The surface is reachable, the technique is well known, and prior evidence exists here or in similar systems. |
| `almost_certain` | Actively exploited in the wild, or trivially automatable against the default configuration. |

Evidence (past CVEs in the same surface, pentest findings, public exploit code)
moves likelihood **up**. Existing controls move it **down**. Score the
**residual** likelihood after current controls.

---

## Example (excerpt — a web service)

```markdown
## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
| T1 | Cross-tenant disclosure of scan history / API keys via missing ownership check | remote_auth | dashboard + history API | user scan data, API keys | high | possible | unmitigated | per-route auth middleware | |
| T2 | Server-side request forgery / policy bypass via attacker-controlled redirect on MTA-STS fetch | remote_unauth | MTA-STS policy fetch | service integrity, internal network | high | possible | partially_mitigated | redirect: manual + opaqueredirect guard | #58, #92 |
| T3 | Stored XSS via unescaped DNS record content rendered into the HTML report | remote_unauth | /check HTML report | report viewer's session | medium | possible | partially_mitigated | esc() on interpolated values | |
| T4 | Billing privilege escalation (free → paid features) via forged or unverified Stripe webhook | remote_unauth | Stripe webhook endpoint | subscription state | high | rare | unmitigated | webhook signature verification | |
```

T1 stays in the model after any single missing-predicate bug is fixed: the
class of "a query that forgets to scope by the caller's identity" persists.
The evidence column lists specific past instances; the threat is the pattern.
