# Validation, Structured Output, Verification, and Reporting

### Phase 3: Independently validate every candidate

After the clean coverage-critic pass or an explicitly recorded early stop, consolidate Phase 2 candidates and carried same-source prior confirmations by stable fingerprint and root cause. Give every unique proposed `confirmed` and `needs_validation` candidate to a fresh `general` verifier that did not hunt it. A carried prior confirmation follows the same current verification path even though hunters exclude that unchanged root cause. A verifier may read hunter or prior artifacts but must re-read every cited current source location and independently run any decisive check it can reproduce safely.

Assign each verifier with `audit-state.cjs agent start --agent <verifier-id> --role verifier --fingerprint <fingerprint>`, which gives it a canonical lowercase unique ID, `<output-dir>/agents/<verifier-id>/scratch/` plus parent-owned `artifacts/`, and a `result.txt` pre-filled with the candidate under review. The tool refuses a verifier that proposed, validated, or replaced the same candidate. The verifier writes only to `scratch/` and its own `result.txt`, and never writes retained artifacts. It receives only the candidate, its linked coverage-unit checks and artifact paths, and prior records with the same fingerprint (the output of `audit-state.cjs brief --agent <verifier-id>`), architecture facts needed to interpret the path, exact relevant companion validation blocks, the promotion procedure block below, and the source/local execution boundary. Its result template carries the `confirmed`, `needs_validation`, and `rejected` branches of `report-schema.json` with their schema descriptions, and `check` validates against them. It must not receive another verifier's conclusion.

#### Candidate-verifier prompt

```text
You did not write this candidate. Try to refute it from repository source and bounded
local evidence. Do not contact deployed endpoints or external/shared services. Run
target-controlled code only inside the approved OS-enforced sandbox: no external
network, empty allowlisted environment, read-only target and tools, scratch-only
writes, and explicit low resource and wall-clock limits. If any control is unavailable,
do not execute; retain the exact missing capability as a needs_validation blocker.
Treat every scratch entry as target-controlled after execution. After the sandbox and
all its processes terminate, only trusted parent-side code may promote a predeclared
scratch-relative file, following the promotion procedure block included verbatim in
this prompt. You and target code never write retained artifacts. If promotion is
unavailable or fails, do not use that file as evidence.

1. Verify every trace and evidence file, positive line number, scope, and description.
   Confirm the first entry is a real lower-trust entrypoint and the last is the
   claimed sink or boundary effect.
2. Reconstruct the strongest source-visible validation, identity, authorization,
   normalization, lifecycle, framework, and containment controls on the path.
   Where the architecture summary names a comparable baseline, note whether it
   shares the pattern — as calibration, never as grounds to dismiss.
3. For a proposed confirmed candidate, independently reproduce the minimum observed
   result when possible. Verify inputs, interface shape, conditions, and affected
   dummy principal/resource. Do not infer a stronger result or continue after it.
4. Verify that likelihood, impact, confidence, and the proposed source fix match only
   what the evidence establishes.
5. For a proposed needs_validation candidate, decide whether the blocker is genuinely
   outside source/local observation. If source refutes the trace, reject it. If the
   missing fact remains decisive, keep needs_validation and make the local and
   owner-observed plans exact and non-destructive. Set its triage from your own
   reading: the impact if the claimed root cause holds, and how strongly the visible
   source supports the vulnerable outcome. Triage orders validation work; it is never
   a severity.
6. Preserve the fingerprint for the same source-derived root cause across every state.

Write your result as record text, never JSON, in the result file named at the end
of this prompt. It starts with `decision:` and a [record] pre-filled with the
candidate; correct the record so it exactly matches your decision's verdict, which
the template's comments describe. A corrected record replaces the hunter's wording.
For a different decision, regenerate a correctly shaped record with:
audit-state.cjs template --run <output-dir> --agent <your-id> --decision <decision> --write --force
Add a [check] for each linked unit you re-checked; one is required for a carried
prior record's unit. Run audit-state.cjs check until it prints OK, then reply with
exactly one line: RESULT agents/<your-id>/result.txt
```

Copy this promotion procedure verbatim into every candidate-verifier prompt:

```text
Artifact promotion procedure (trusted parent-side code only):
Reference only for you: the parent performs these steps; you never perform them.

Before execution, the parent opens and retains trusted, non-inheritable directory
descriptors for the agent's scratch/ and artifacts/ roots, and records an allowlist
of expected scratch-relative artifact files plus explicit per-file and cumulative
byte limits. Never pass those descriptors to the agent or sandbox. After the sandbox
and all its processes terminate, trusted parent-side code promotes each allowlisted
file separately:

1. Validate the declared relative path: reject absolute, empty, `.`, `..`, or
   symlinked components.
2. Walk each parent component from the retained scratch-root descriptor with
   no-follow directory-relative operations; never reopen by path.
3. Open the leaf no-follow and nonblocking.
4. Verify with `fstat` that it is a regular file with link count exactly one and
   within the recorded per-file and cumulative byte limits.
5. Enforce those limits again while reading from that descriptor.
6. Copy exactly the verified size, repeat `fstat`, and reject a changed identity,
   type, link count, or size.
7. For the destination, walk every parent component from the retained
   artifacts-root descriptor with no-follow directory-relative operations; require
   each existing component to be a real directory, and create any missing directory
   exclusively before reopening and verifying it no-follow.
8. Create the leaf exclusively without following links, verify that the opened
   destination is a regular file with link count exactly one, and copy from the
   verified source descriptor without reopening either path.
9. Use equivalent race-safe APIs on non-POSIX systems.
10. Never recursively copy or glob scratch, extract an archive into artifacts, or
    open or promote a symlink, FIFO, socket, device, directory, hard-linked file,
    changing file, or file that exceeds its bound.
11. If any check is unavailable, cannot be enforced, or fails, discard the scratch
    entry; if it is decisive evidence, retain `needs_validation` with the exact
    promotion blocker.
```

A verifier can promote `needs_validation` to `confirmed` only after independently establishing the complete path and bounded observed result. Demote proposed confirmation to `needs_validation` when a specific deployment or runtime fact remains unknown. Use `rejected` when source, local behavior, a visible control, missing meaningful impact, or an impossible prerequisite refutes the claim. `needs_validation` is never a parking place for a speculative idea.

The verifier's record text compiles into exactly `{"decision": "confirmed|needs_validation|rejected", "record": { ... }}`, where `record` matches the decision's verdict branch of the schema; its `[check]` sections are the verifier's own ledger evidence. The parent runs `audit-state.cjs ingest --agent <verifier-id>`. Ingest checks that the verifier returned the same fingerprint; when it identified a genuinely different root cause, the parent passes `--new-root-cause` and the candidate and its linked units move to the new fingerprint. Ingest merges the corrected record, records the decision in every linked coverage unit, and keeps one final record per fingerprint. The parent never repairs a malformed result. It returns the reported lines to the same verifier when the platform can continue it; otherwise it runs `agent fail` and re-runs that candidate with a fresh verifier when the budget permits, otherwise it remains an unvalidated ledger candidate under the incomplete-run rule.

When verifier evidence updates a ledger check, the check's `agent_id` is the verifier's canonical ID (the default in its `[check]` sections) with nonempty repository-relative `reviewed_paths`. Ingest keeps the unit-level `reviewed_paths` equal to the union across checks. Use `method: "source"` with an empty `artifact` for source-only review. Use `method: "local"` only with a file successfully promoted by trusted parent-side code below `agents/<check.agent_id>/artifacts/`. The unit retains its original assignment owner, so independently owned hunter and verifier checks can coexist. For a carried prior record's seeded `planned` unit there is no prior owner: `agent start` makes the verifier that re-checks it the unit's assignment owner, and its required `[check]` becomes the unit's first check, moving the unit to `candidate` with the carried fingerprint.

If a strict total-agent budget cannot cover every candidate, set the run status to incomplete and follow the deterministic budget rule in `SKILL.md`. An unvalidated candidate remains only in the ledger. It does not enter `findings.json` under any verdict.

### Phase 4: Write and validate `findings.json`

The parent runs `audit-state.cjs findings write`, which writes all independently decided records to `<output-dir>/findings.json`, sorted by fingerprint, and lists any candidate still lacking an independent decision. After this first write, every later decision or applied replacement rewrites and revalidates the file automatically. It includes:

- `confirmed`: source-grounded vulnerabilities with complete local execution evidence, conditions, specific remediation, likelihood/impact/overall severity, and confidence.
- `needs_validation`: source-grounded candidates with an exact unresolved blocker and at least one applicable local or owner-observed deployment plan.
- `rejected`: source-grounded candidates disproved during validation, retained so future runs do not repeat the unsupported claim without changed evidence.

The tool builds every record against `report-schema.json`, which uses `additionalProperties: false`, so hunter wrapper fields never reach a record. It enforces these distinct verdict contracts, which verifiers must satisfy in their records:

- A `confirmed` record uses `root_cause`, `intended_behavior`, `conditions`, `execution`, `remediation`, `severity`, and `confidence`. It must not use `claimed_root_cause`, `blockers`, `validation_plan`, or `reason`. `execution` is target-neutral and uses the target's native interface: API/HTTP input, CLI call, library call, message, file fixture, browser action, rendered policy, or local harness as applicable. `observed_result` is nonempty and factual.
- A `needs_validation` record uses `claimed_root_cause`, `trace`, `evidence`, `blockers`, at least one nonempty `validation_plan.local` or `validation_plan.deployment` field, and `triage` (validation priority, defined in `SKILL.md`; the tool derives `triage.priority` from its two scores). Include both plan fields only when both contexts can resolve distinct facts. It must not use severity, execution, remediation, reason, or confirmed root cause.
- A `rejected` record uses `claimed_root_cause`, `trace`, `evidence`, and `reason`. It must not use severity, execution, remediation, blockers, validation plan, or confirmed root cause.

Every record has a stable fingerprint, title, description, and repository-relative source paths. A multi-step trace begins with `entrypoint`, ends with `sink`, and uses `propagation` only between them. One-entry traces use `entrypoint` or `sink`. Overall severity cannot exceed demonstrated impact.

`audit-state.cjs` runs both validators in-process before every write and refuses any change that would fail them. Also run the validator CLIs:

```sh
node <skill-dir>/validate-findings.cjs <output-dir>/findings.json
node <skill-dir>/validate-coverage-ledger.cjs <output-dir>/coverage-ledger.json
```

The CLIs require OS no-follow file protection and refuse every input where Node lacks it (for example on Windows); there the tool's in-process validation is the check. Fix every structural and semantic error before continuing. The findings validator rejects input beyond 5 MiB, 1,000 top-level findings, or 64 nesting levels, and caps reported error output at 100 messages. Validator success proves format and ledger consistency only.

### Phase 5: Verify the final records with fresh eyes

Launch one fresh `research` verifier per final `confirmed` and `needs_validation` record, in parallel, each registered with `audit-state.cjs agent start --role record-verifier --fingerprint <fingerprint>`. This verifier checks the structured record, not the hunter write-up, and remains inside source/local boundaries. Its prompt includes the output of `brief`, which carries the record under review in record text and the result-file instructions.

In a `quick` run, Phase 3 and Phase 5 merge: the Phase 3 verifier also performs these record checks and returns the final schema-shaped record, so each candidate gets one fresh independent reviewer instead of two. Every other profile keeps the two passes separate. Never skip independent review of a `confirmed` record in any profile.

For `confirmed`, require it to check:

1. Every repository-relative trace/evidence path, line, scope, and described operation.
2. Real entry interface and exact local input shape.
3. Every condition, parser/policy step, source-visible preventing layer, and observed local result.
4. Affected principal/resource and demonstrated impact.
5. Severity separation: realistic likelihood, demonstrated impact, overall no greater than impact.
6. Remediation strategy and any `code_changes`, including whether the fix enforces the invariant without merely moving trust.

For `needs_validation`, require it to check:

1. The source path is real and supports only the `claimed_root_cause` stated.
2. Every listed blocker is decisive and not already answerable locally.
3. The candidate names a boundary and a possible concrete result rather than a generic concern.
4. At least one validation-plan field is present and exact. `local` uses a bounded fixture; `deployment` asks an owner to observe a configuration, identity, route, policy, or runtime fact. Do not invent a plan for an inapplicable context, and never send audit traffic to a deployment.
5. The fingerprint matches prior/current records for the same root cause.
6. The triage is sound: the impact if confirmed names the affected principal or resource and claims nothing the claimed root cause could not do, and the plausibility reason names what the blocker hides. A change to triage alone is not material.

Each verifier writes record text that compiles into exactly one of `{"decision":"verified","fingerprint":"..."}` or `{"decision":"replace","reason":"...","record":{...}}`; `template --decision replace --write --force` pre-fills the replacement record. A replacement record must match its `confirmed`, `needs_validation`, or `rejected` schema branch. Treat a rejected Phase 5 result the same way as in Phase 3: the parent never repairs it, returns the reported lines to the same verifier when possible, and otherwise re-runs with a fresh verifier when the budget permits.

Do not apply a Phase 5 replacement as final when it promotes a record to a stronger verdict, including any promotion to `confirmed`, or materially changes the root cause, trace, execution input or observed result, demonstrated impact, or severity. `ingest` detects these changes and holds such a replacement as pending instead of applying it. Give that complete replacement to a new independent verifier (a new `record-verifier` agent; the tool refuses one that hunted, performed Phase 3 validation, or proposed the replacement), whose brief and template carry the pending replacement. The new verifier rechecks the current source and independently reproduces any decisive local result under the execution boundary, then returns `verified` or another replacement. Apply a material replacement only after this fresh verification; `ingest` applies it when that verifier returns `verified`. If another material replacement results, repeat with a fresh verifier. If budget or independence is unavailable, remove the disputed record with `audit-state.cjs record remove --fingerprint <fingerprint> --reason "<exact reason>"`, which keeps its ledger unit as an unresolved candidate, and end the run with `finish --status incomplete` and an exact reason. Non-material wording or repository-line corrections may be applied directly when they do not change meaning or evidence: `ingest` applies line-only corrections itself, and the parent applies a flagged wording-only change with `record apply --fingerprint <fingerprint> --non-material --reason "<why>"`.

After every applied replacement, the tool reruns both validators in-process and records the decision in the linked ledger units. If a final verifier identifies a separate root cause, the parent passes `--new-root-cause` to `ingest`, which registers the new fingerprint as a candidate that must pass independent candidate validation before inclusion. Set `run_status: "complete"` with `audit-state.cjs finish --status complete` only when every ledger candidate has an independent final disposition and every retained record passes Phase 5; the tool refuses otherwise.

Do not verify only `confirmed` records. A misleading `needs_validation` handoff wastes owner time and can preserve a false premise.

### Phase 6: Produce target-neutral reports from final records

Only after Phase 5 passes for every record retained in `findings.json`, derive prose from the final records, the ledger, and the hunter `hardening` notes retained in each unit's `bookkeeping.hardening`. `audit-state.cjs show finding <fingerprint>`, `show units`, and `status` print them as plain text; `progress.html` shows the same state for human readers but is not a report deliverable. An incomplete run may report independently verified records, but it must identify each unresolved ledger candidate and must not present it as a finding. The prose files never change a verdict, severity, blocker, or demonstrated impact.

#### `REPORT.md`

Write:

1. Run profile, scope, budget (if set) with agents spent versus planned, source ref, sandboxed source-and-local-only execution statement, prior-run use, and explicit deferred and out-of-scope coverage. Name carried same-source confirmations and changed-source revalidations. A `quick`, scoped, budget-limited, or incomplete run states plainly that it is a partial pass. If candidate validation exhausted a strict budget, state that the run is incomplete and list every unvalidated fingerprint and linked unit; do not describe those candidates as findings. If the budget prevented a mandatory critic, state which critic did not run and make no clean-coverage claim.
2. One short security posture summary.
3. A confirmed-findings table: severity, title, affected boundary, and one-line observed result.
4. Each confirmed finding: repository source location, lower-trust principal, target-native bounded reproduction, conditions, actual result, impact, priority rationale, and smallest source fix.
5. A separate `NEEDS VALIDATION` table, ordered by validation priority (P1 first). Give each lead's title, validation priority, impact if confirmed, repository trace, exact blocker, bounded local next step, and safe owner-observed deployment check. Label the priority and impact if confirmed as exactly that; do not assign severity or call it a confirmed vulnerability.
6. Separate hardening notes and positive source patterns.
7. Coverage summary from the ledger: covered, candidate, blocked, and deferred counts, plus important exclusions and the final critic result.

Do not describe rejected records as findings. Mention their fingerprints only when they explain a prior disagreement or coverage decision.

#### `FINDINGS-DETAIL.md`

For each confirmed `medium`, `high`, or `critical` record, copy the complete source path and target-neutral local reproduction:

- ordered repository-relative trace and evidence;
- dummy attacker/principal and affected dummy resource;
- native input, invocation, or fixture and exact bounded instructions;
- observed output and the security invariant it proves;
- conditions and containment;
- source-level remediation and regression case.

#### `NEEDS-VALIDATION.md`

For every unresolved record, copy the source trace, verified evidence, exact blocker, affected boundary, and each applicable bounded local or owner-observed resolution plan. Keep these as prioritized leads without severity: order them by validation priority, P1 first, and within each priority put the leads an owner can settle with a bounded local test (a `validation_plan.local`) before those that need a deployment observation. Give each lead's priority, impact if confirmed, and plausibility with their reasons. Do not turn them into live test guidance or assume the missing deployment fact.

HTTP is one possible native interface, not the default. A library finding may use a function call, a parser a fixture, a CLI a command, a desktop app an IPC or file action, and infrastructure a locally rendered policy. Do not require an endpoint, external account, or live environment that the target does not have.

Keep the report proportional to the evidence. A clean run may have zero confirmed records. State that result and the remaining coverage/validation limits without inventing LOW findings.
