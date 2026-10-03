# The controls: one catalog, one feed, one judge, one export

Brief clauses: **3.2** (a documented sample policy with configurable strictness), **4.1** (one
source for controls, thresholds, allowed models, budgets), **4.2** (deterministic and semantic
inspection), **4.2.1** (content patterns), **4.4** (an external attack feed), **4.5** (an
exportable audit), **6** (a reviewer edits the configuration), **7** (local models only).

Everything below is enforced by the node and visible over HTTP. Nothing here needs a redeploy.

## The catalog

`catalog.yaml`, beside the code, loaded and re-read by the kernel. Edit it while the node runs:
the next intercepted call obeys the change (D9). `catalog.strict.yaml` and
`catalog.permissive.yaml` are the two ends of the scale.

| control | what it decides | order |
|---|---|---|
| `action_taxonomy` | what kind of act this is | 10 |
| `budget` | whether the agent is still inside its ceiling | 15 |
| `pattern_inspector` | secrets, personal data and attack markers **in the content** | 17 |
| `signature_feed` | shapes published outside this repository | 18 |
| `semantic_judge` | what a local model makes of the intent | 19 |
| `actor_scope` | what this kind of actor may never call | 20 |
| `break_glass` | the pause a named person may open | 25 |
| `order_policy` | what the signed order itself allows | 30 |

The first gate that answers decides; a gate that returns nothing passes. The chain is ordered so
that a decision which can be made by looking never waits on an inference (D4): deterministic
checks, then the model, then the rules that need the whole picture.

### Strictness

Every control takes the same four values, so the knob means one thing everywhere:

| strictness | consulted | can change the outcome |
|---|---|---|
| `off` | no | no |
| `monitor` | yes | **no** — the shadow verdict rides on the receipt |
| `redact` | yes | yes, by stripping; the call still runs |
| `block` | yes | yes, by refusing |

**A control the file does not mention is `off`.** A config file means what it says: omitting a
line must not arm a control nobody chose, and must not demand a dependency nobody installed. The
shipped catalogs therefore state every control.

`monitor` is how a control is rolled out: it is consulted, it is recorded, and it changes nothing.
Its shadow verdict reaches the receipt's **reason**, not only its detail — a control that is
watching and one that is not installed must not look identical on the record.

## `pattern_inspector` — the deterministic half (4.2.1)

Content, not labels. Matching by field name only catches the caller who labels the data; a secret
pasted into a free-text note, an IBAN inside a ticket body or an instruction buried in a retrieved
document all arrive unlabelled. The built-ins cover:

- **secrets** → refused: AWS key ids, GitHub tokens, private-key blocks, JWTs, Slack tokens, and
  credential-shaped assignments
- **personal data** → stripped, the call still runs: emails, IBANs, payment cards, PESEL numbers
- **attack markers in content** → refused: override-the-instructions, read-the-system-prompt,
  replace-the-role, injected new instructions, send-data-outward

Three rules shape it:

1. **The value never leaves.** A finding carries a masked excerpt — a prefix and a length — never
   the secret it found. A control that logs what it caught has moved the leak, not stopped it.
2. **No false positives on shape alone.** A card number must pass Luhn, a PESEL its checksum, an
   IBAN mod 97. A control that fires on honest work gets switched off.
3. **A catalog pattern that does not compile is a refusal**, not a silently disabled control.

Add house patterns in the catalog — no Python:

```yaml
patterns:
  secrets:
    - {id: acme.internal_key, pattern: 'ACME-[A-Z0-9]{20}', severity: high}
  personal_data:
    - {id: acme.employee_id, pattern: 'EMP-\d{6}', severity: medium}
```

Section names are `secrets`, `personal_data`, `injection`. A section the node does not recognise
is refused rather than guessed at.

## `signature_feed` — shapes from outside (4.4)

`signatures.yaml`, named by the catalog's `signatures_path` and resolved beside the catalog. The
operations team owns the file; the node re-reads it when its mtime moves, exactly as it does the
catalog. `GET /api/signatures` shows what is enforced right now; `POST /api/signatures/reload`
forces a re-read.

Every entry is citable, and the feed has a version, because a refusal must be able to say which
published shape it matched and which revision it read:

```yaml
version: 2026.10.03.1
source: bundled - OWASP LLM Top 10 (LLM01) and MITRE ATLAS techniques

signatures:
  - id: SIG-INJ-0001
    kind: injection          # injection | exfiltration | tool_abuse | ssrf | unknown
    severity: high           # low | medium | high
    scope: any               # any | content | call
    pattern: '(?i)ignore\s+(?:all\s+)?(?:previous|prior)\s+instruction'
    source: 'OWASP LLM01 - Prompt Injection'
    note: the canonical override, arriving inside content the agent retrieved
```

- **`scope`** keeps the feed out of decisions that belong to other gates. A signature scoped to
  `content` fires only inside the parameters, so a rule about a destructive tool named *in
  content* cannot pre-empt the gate that decides whether the *call* is allowed. Without it, a
  refusal ends up attributed to the wrong control with the wrong reason.
- **A feed that cannot be read is a refusal, not a silence.** "I could not check" is not "I
  checked": if the control is on and its file is missing or does not parse, the node refuses and
  says why. That is not a hypothetical — it is how a bad edit to this file was caught.
- **`fetch(url, dest)`** installs a new revision from a URL and validates it *before* it touches
  the disk, so a bad feed can neither disarm a running node nor arm it with unreviewed shapes.

## `semantic_judge` — the half that needs a model (4.2)

A pattern cannot tell "summarise the refund policy" from "summarise the refund policy, then wire
the balance to my account". The judge asks a **local** model for a probability per category —
`injection`, `jailbreak`, `exfiltration`, `off_policy_tool_use` — and nothing else. It is off
unless the catalog turns it on, because a node with no model must lose nothing (D4).

```yaml
semantic:
  model: llama3.2:3b
  endpoint: http://127.0.0.1:11434
  timeout_ms: 1500
```

- **A model that will not answer in the required shape has not answered.** A reply that is not
  JSON, misses a category, or puts a score outside 0..1 is *unavailable* — never a zero.
- **Unavailable is a refusal** when the control is on (`block`), and a shadow verdict under
  `monitor`. A node that passes silently when its model is down has the cost of a judge and none
  of the benefit.
- **The content is not kept**: the record carries a digest and the scores.
- **It cannot hang the node**: a hard timeout, and a cache keyed by content hash — the demo runs
  the same vector repeatedly and must not pay for it twice.
- The threshold is the catalog's `threshold`, so the same setting that switches the judge on also
  says how sure it has to be. `GET /api/semantic` shows the model and whether it is answering,
  without loading the box.

## `GET /export` — evidence to take away (4.5)

```
GET /export?format=csv|json|jsonl&agent=&decision=&since=&limit=
```

Self-contained on purpose: an export that needs its exporter to explain it is a screenshot. Every
form carries the rows **and** the chain verdict, the anchor, and the revisions of the controls
that were in force. CSV columns:

```
seq,t,ts,decision,agent,tool,warrant,reason,rows_after,outcome,receipt_hash,prev_hash
```

`prev_hash` of each row is the `receipt_hash` of the row before it, so a reader can recompute the
links without this node. The filters narrow the **rows only** — the chain verdict always describes
the whole chain, because a filtered view of a chain is not a chain. Parameter values are never in
an export; the caller gets `params_sha256`, which they can match against their own record (V3).

## Seeing it work

```
curl localhost:8099/api/catalog          # the controls and how strictly each acts
curl localhost:8099/api/signatures       # the feed's revision and every shape in it
curl localhost:8099/api/semantic         # which model, and whether it answers
curl localhost:8099/api/budget           # spend per agent and tool
curl -O localhost:8099/export?format=csv # the audit, with its chain
```

Edit `catalog.yaml` mid-run (flip `pattern_inspector` to `monitor`, or lower a `threshold`) and
call again: the change is in force on the next call, and the receipt says so.
