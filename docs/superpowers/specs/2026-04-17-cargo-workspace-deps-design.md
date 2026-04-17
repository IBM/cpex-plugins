# Cargo Workspace Dependency Consolidation Design

## Goal

Make the Rust plugin crates rely on the root Cargo workspace for as many shared dependencies as possible so version selection is centralized and plugin manifests do not drift apart.

## Scope

This change only covers Rust `Cargo.toml` files in this repository.

In scope:

- Root workspace dependency declarations in `/Users/luca/.codex/worktrees/6dc9/cpex-plugins/Cargo.toml`
- Plugin crate manifests under `/Users/luca/.codex/worktrees/6dc9/cpex-plugins/plugins/rust/python-package/*/Cargo.toml`
- Lockfile refresh caused by manifest changes

Out of scope:

- Python `pyproject.toml` files
- `uv.lock` files
- Plugin code changes
- Dependency version upgrades beyond what is required to centralize already-used versions

## Current State

The root workspace already defines members and a small set of shared dependencies. Plugin manifests still repeat several common dependencies directly:

- Shared local crate path: `cpex_framework_bridge`
- Shared dev dependency: `criterion`
- Shared third-party crates used by multiple plugins, such as `regex`

Some plugin manifests already use workspace shorthand syntax, while others use inline tables. The result is partial centralization and inconsistent manifest style.

## Requirements

1. All existing plugin crates remain workspace members.
2. Every dependency that can be shared across multiple plugin crates without changing behavior should be sourced from `[workspace.dependencies]`.
3. Plugin-specific dependencies stay local to the plugin manifest.
4. No dependency versions should change unless required to preserve the currently resolved shared version.
5. Cargo metadata and workspace checks must continue to pass.

## Chosen Approach

Use the root workspace `Cargo.toml` as the single source of truth for shared Rust dependencies and normalize plugin manifests to consume those dependencies via `workspace = true`.

### Root workspace changes

Add shared entries to `[workspace.dependencies]` for:

- `cpex_framework_bridge` using its existing relative path from the repository root
- `criterion` with the existing `html_reports` feature
- Shared third-party crates currently repeated across plugin manifests, including `regex`

Keep existing workspace dependency entries unchanged unless a direct conversion to workspace ownership is needed.

### Plugin manifest changes

For each plugin under `/Users/luca/.codex/worktrees/6dc9/cpex-plugins/plugins/rust/python-package`:

- Replace repeated shared dependency declarations with `workspace = true`
- Replace repeated shared dev dependency declarations with `workspace = true`
- Preserve plugin-only dependencies such as `base64`, `serde`, `uuid`, `redis`, `parking_lot`, and similar single-plugin crates as local declarations
- Normalize workspace dependency syntax consistently across all plugin manifests

### Version policy

Do not introduce new versions. Reuse the versions already present in the repository so the lockfile change is limited to workspace centralization, not upgrades.

For crates repeated with equivalent versions, move that version to the workspace and remove local duplication.

## Alternatives Considered

### 1. Minimal deduplication only

Only move obviously duplicated third-party crates, leaving path and dev dependencies repeated.

Rejected because it would still leave avoidable duplication and would not satisfy the user's request to import as much as possible from the workspace.

### 2. Full manifest refactor including package metadata

Move more package metadata and restructure manifest formatting broadly.

Rejected because it creates unnecessary churn unrelated to dependency centralization.

## Risks

### Relative path correctness

Moving `cpex_framework_bridge` to workspace dependencies requires the root manifest path to be correct from the repository root. This must be verified carefully because the current plugin manifests use a different relative base.

### Feature preservation

Moving `criterion` and any other crates with features into the workspace must preserve existing features exactly.

### Mixed syntax normalization

Converting all shared dependencies to workspace form should avoid touching plugin-specific declarations so the diff stays surgical.

## Verification

Run at least:

- `cargo metadata --format-version 1`
- `cargo check --workspace`

If either command reveals path or dependency issues, correct the workspace declarations before concluding the task.

## Success Criteria

- Shared Rust dependencies are declared once in the root workspace manifest wherever practical.
- Plugin manifests consume those shared dependencies via `workspace = true`.
- Plugin-specific dependencies remain local.
- The workspace resolves and checks successfully.
