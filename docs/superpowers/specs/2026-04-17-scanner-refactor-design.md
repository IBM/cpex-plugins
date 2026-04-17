# Scanner Refactor Design

## Goal

Reduce the size and cognitive load of `plugins/rust/python-package/secrets_detection/src/scanner.rs`
without changing public API or runtime behavior.

## Constraints

- Preserve all current external functions:
  - `scan_container`
  - `scan_value`
  - `py_to_value`
  - `value_to_py`
  - `findings_to_pylist`
  - `detect_and_redact`
- Do not change plugin behavior, redaction semantics, cycle handling, object rebuild behavior,
  or test expectations.
- Keep the refactor local to the `secrets_detection` plugin.
- Prefer moving code over inventing new abstraction layers.

## Problem

`scanner.rs` currently owns four separate concerns:

1. Python object graph traversal and redaction.
2. Cycle placeholder rewriting.
3. JSON/Python conversion helpers.
4. Regex-based text scanning and redaction.

That makes the file large and forces readers to keep unrelated logic in working memory at once.
The file is not too long because one algorithm is inherently large. It is long because several
distinct responsibilities are combined.

## Proposed Structure

Create a `src/scanner/` module directory and keep `src/scanner.rs` as the public facade.

Planned files:

- `src/scanner.rs`
  - Public exports and thin orchestration.
  - Declares submodules.
- `src/scanner/python_scan.rs`
  - Recursive Python container traversal.
  - Object-state handling.
  - Serialized-state decision logic.
- `src/scanner/cycle_rewrite.rs`
  - Placeholder replacement and cycle rewrite traversal.
- `src/scanner/value_conversion.rs`
  - `py_to_value`
  - `value_to_py`
  - `findings_to_pylist`
- `src/scanner/text_scan.rs`
  - `Finding`
  - `detect_and_redact`

## Module Boundaries

### `text_scan.rs`

Owns only text-oriented scanning behavior and the `Finding` type.

Reasons:

- `Finding` exists to describe regex matches.
- `detect_and_redact` is logically independent from Python traversal and value conversion.
- This file should remain small and easy to test in isolation.

### `value_conversion.rs`

Owns conversion between Python values and `serde_json::Value`, plus Python rendering of findings.

Reasons:

- Conversion helpers are utility behavior, not traversal behavior.
- They already operate mostly independently.
- Grouping them keeps data-shape translation separate from secret-detection flow.

### `cycle_rewrite.rs`

Owns placeholder-rewrite traversal used after tuple reconstruction.

Reasons:

- This logic is specialized and easy to reason about when isolated.
- It depends on object rebuild support, but it is not part of the main scan loop.
- Separating it makes tuple-cycle behavior easier to review.

### `python_scan.rs`

Owns the recursive `scan_container` implementation and object/serialized-state decisions.

Reasons:

- This is the actual high-complexity runtime path.
- Keeping all recursive scan-state handling together is clearer than spreading it across files.
- This module can import `detect_and_redact` and cycle rewrite helpers instead of owning both.

## Public API Shape

The crate-facing surface remains unchanged.

`src/scanner.rs` will re-export the existing functions so current callers and tests do not need
to change imports or call sites.

## Refactor Approach

1. Introduce `src/scanner/` submodules.
2. Move `Finding` and `detect_and_redact` into `text_scan.rs`.
3. Move value conversion helpers into `value_conversion.rs`.
4. Move placeholder rewrite logic into `cycle_rewrite.rs`.
5. Move recursive Python scanning logic into `python_scan.rs`.
6. Reduce `src/scanner.rs` to module declarations and re-exports.
7. Run formatting, clippy, and full plugin tests after the move.

## What Will Not Change

- No regex changes.
- No config changes.
- No object model changes.
- No packaging/build/test layout changes.
- No new feature flags or extension points.
- No new generic helper layer.

## Risks

### Import churn

Moving functions across modules can create circular dependencies or noisy imports.

Mitigation:

- Keep dependency direction simple:
  - `python_scan` depends on `text_scan` and `cycle_rewrite`.
  - `cycle_rewrite` may depend on object-model helpers.
  - `value_conversion` depends only on `text_scan` types and `serde_json`/PyO3 utilities.

### Behavior drift during move

The main risk is accidentally changing ownership, cloning, or cycle behavior while relocating code.

Mitigation:

- Prefer copy/move with minimal edits.
- Keep function bodies as intact as possible in the first pass.
- Let existing integration coverage validate equivalence.

## Verification

Required commands:

```bash
make check-all
make test-all
```

Expected outcome:

- `cargo fmt -- --check` passes.
- `cargo clippy -- -D warnings` passes.
- Rust tests pass.
- Python integration tests pass unchanged.

## Success Criteria

- `scanner.rs` becomes a thin facade instead of a 600+ line mixed-responsibility file.
- New module layout reflects real concerns without adding speculative abstraction.
- Public API remains unchanged.
- Full existing test suite stays green.
