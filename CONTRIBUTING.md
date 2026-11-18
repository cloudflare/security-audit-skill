# Contributing

Thanks for helping improve the security-audit skill. This guide covers what is specific to this repository. The Cloudflare-wide [contributing guide](https://github.com/cloudflare/.github/blob/master/CONTRIBUTING.md) and [Code of Conduct](https://github.com/cloudflare/.github/blob/master/CODE_OF_CONDUCT.md) also apply.

## Before you open a pull request

- **Open an issue first** for new attack classes, companion files, workflow changes, or schema changes, so the design can be discussed before you write it. Typo and small correctness fixes do not need one.
- **Search open pull requests.** Many changes touch the same few files, especially the two validators. If an open PR already covers your change, review or build on it instead of opening a parallel one, and link related PRs in your description.
- **Keep one change per pull request.** A validator fix, a prompt change, and a new companion are three PRs.

Do not report vulnerabilities in this repository through public issues or pull requests. See [SECURITY.md](SECURITY.md).

## Repository layout

The installable skill lives in `skills/security-audit/`. Everything an agent loads at run time must stay inside that directory so `npx skills add` installs it. Repository-only files (this guide, CI, templates) stay at the root or in `.github/`.

## Standards

- **One house style.** Match the structure, terminology, and tone of the surrounding files. Domain companions share one section schema: `When to use this file`, a fenced `Core discipline` block, attack classes tagged with `subagent_type`, `Universal moves`, and `Validation rules`. Hunter prompts reference these headings by name.
- **Verbatim blocks stay identical.** Blocks marked to be copied verbatim into prompts, such as the artifact promotion procedure, must change in every copy at once.
- **Prose and schema agree.** A change to a verdict, field, or state in `report-schema.json` or the coverage ledger contract needs the matching change in the Markdown that describes it, and the reverse.
- **The validators have no dependencies.** `validate-findings.cjs` and `validate-coverage-ledger.cjs` use only the Node.js standard library. Keep their input limits, safe-open behavior, and capped, sanitized error output intact.
- **The evidence bar does not move.** Changes must not let a finding be confirmed without a complete source trace and bounded local evidence, or relax the sandbox and `needs_validation` rules.

## Testing

Run both suites from `skills/security-audit/` with a current Node.js LTS release:

```sh
node --test validate-findings.test.cjs validate-coverage-ledger.test.cjs
```

Add or update tests for any validator or schema change. In the pull request, list the commands you ran and what they showed.

## Commits and pull requests

Write commit subjects as short imperative sentences, for example `Reject invalid trace line numbers`, and explain why in the body. Fill in the pull request template and link the issue it resolves with `Closes #<number>`.
