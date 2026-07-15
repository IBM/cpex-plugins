// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
//
// Rust-owned SQL sanitizer plugin core.
// Python only keeps a thin compatibility shim so the gateway can import a
// `Plugin` subclass while all logic lives here.

use cpex_framework_bridge::{build_framework_object_dyn, default_result as bridge_default_result};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyModule};

use crate::config::SqlSanitizerConfig;
use crate::scanner::scan_args;

const LOGGER_NAME: &str = "cpex_sql_sanitizer.sql_sanitizer";

/// The Rust-owned core exposed to Python as a single `#[pyclass]`.
///
/// The thin Python shim (`sql_sanitizer.py`) creates one instance per plugin
/// life-cycle and delegates every hook call here.
#[pyclass]
pub struct SqlSanitizerPluginCore {
    config: SqlSanitizerConfig,
}

#[pymethods]
impl SqlSanitizerPluginCore {
    /// Construct from a Python `dict` or Pydantic model (the value of `PluginConfig.config`).
    #[new]
    pub fn new(config: &Bound<'_, PyAny>) -> PyResult<Self> {
        let config = SqlSanitizerConfig::from_py_object(config)?;
        Ok(Self { config })
    }

    /// `prompt_pre_fetch` hook — scan prompt arguments for risky SQL.
    #[pyo3(signature = (payload, context, extensions=None))]
    pub fn prompt_pre_fetch(
        &self,
        py: Python<'_>,
        payload: &Bound<'_, PyAny>,
        context: &Bound<'_, PyAny>,
        extensions: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Py<PyAny>> {
        let _ = (&context, &extensions);
        self.handle_pre_hook(
            py,
            payload,
            "PromptPrehookResult",
            "Potentially dangerous SQL detected in prompt args",
        )
    }

    /// `tool_pre_invoke` hook — scan tool arguments for risky SQL.
    #[pyo3(signature = (payload, context, extensions=None))]
    pub fn tool_pre_invoke(
        &self,
        py: Python<'_>,
        payload: &Bound<'_, PyAny>,
        context: &Bound<'_, PyAny>,
        extensions: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Py<PyAny>> {
        let _ = (&context, &extensions);
        self.handle_pre_hook(
            py,
            payload,
            "ToolPreInvokeResult",
            "Potentially dangerous SQL detected in tool args",
        )
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

impl SqlSanitizerPluginCore {
    /// Shared logic for both `prompt_pre_fetch` and `tool_pre_invoke`.
    ///
    /// Outcome priority:
    /// 1. Issues found **and** `block_on_violation=true`  → blocked result with `PluginViolation`
    /// 2. Comments were stripped                          → modified-payload result
    /// 3. Issues found **and** `block_on_violation=false` → pass-through with `metadata.sql_issues`
    /// 4. No issues, no stripping                        → bare default result
    fn handle_pre_hook(
        &self,
        py: Python<'_>,
        payload: &Bound<'_, PyAny>,
        result_class: &str,
        description: &str,
    ) -> PyResult<Py<PyAny>> {
        let args = payload.getattr("args")?;

        let (issues, stripped) = scan_args(&args, &self.config)?;

        // ── 1. Block path ──────────────────────────────────────────────────
        if !issues.is_empty() && self.config.block_on_violation {
            log_violation(py, result_class, &issues)?;

            let details = PyDict::new(py);
            details.set_item("issues", &issues)?;

            let violation = build_framework_object_dyn(
                py,
                "PluginViolation",
                vec![
                    (
                        "reason",
                        "Risky SQL detected".into_pyobject(py)?.into_any().unbind(),
                    ),
                    (
                        "description",
                        description.into_pyobject(py)?.into_any().unbind(),
                    ),
                    (
                        "code",
                        "SQL_SANITIZER".into_pyobject(py)?.into_any().unbind(),
                    ),
                    ("details", details.into_any().unbind()),
                ],
            )?;

            return build_framework_object_dyn(
                py,
                result_class,
                vec![
                    (
                        "continue_processing",
                        false.into_pyobject(py)?.to_owned().into_any().unbind(),
                    ),
                    ("violation", violation),
                ],
            );
        }

        // ── 2. Modified-payload path (comment stripping) ──────────────────
        if !stripped.is_empty() {
            let new_args = rebuild_args_with_stripped(py, &args, &stripped)?;
            let modified = clone_payload(py, payload, "args", &new_args)?;

            let metadata = PyDict::new(py);
            metadata.set_item("sql_sanitized", true)?;
            // In monitoring mode, preserve any detected issues alongside the
            // stripped payload so audit consumers see the full picture.
            if !issues.is_empty() {
                metadata.set_item("sql_issues", &issues)?;
            }

            return build_framework_object_dyn(
                py,
                result_class,
                vec![
                    ("modified_payload", modified),
                    ("metadata", metadata.into_any().unbind()),
                ],
            );
        }

        // ── 3. Monitoring path (issues but not blocking) ──────────────────
        if !issues.is_empty() {
            let metadata = PyDict::new(py);
            metadata.set_item("sql_issues", &issues)?;
            return build_framework_object_dyn(
                py,
                result_class,
                vec![("metadata", metadata.into_any().unbind())],
            );
        }

        // ── 4. Clean pass-through ─────────────────────────────────────────
        default_result(py, result_class)
    }
}

// ---------------------------------------------------------------------------
// Private free functions
// ---------------------------------------------------------------------------

fn default_result(py: Python<'_>, class_name: &str) -> PyResult<Py<PyAny>> {
    bridge_default_result(py, class_name)
}

/// Shallow-copy `args` dict and overlay the comment-stripped values.
fn rebuild_args_with_stripped(
    py: Python<'_>,
    args: &Bound<'_, PyAny>,
    stripped: &[(String, String)],
) -> PyResult<Py<PyAny>> {
    // Start from a shallow copy of the existing args dict so unaffected keys are preserved.
    let new_dict = PyDict::new(py);
    if let Ok(dict) = args.cast::<PyDict>() {
        for (k, v) in dict.iter() {
            new_dict.set_item(&k, &v)?;
        }
    }
    for (key, val) in stripped {
        new_dict.set_item(key, val)?;
    }
    Ok(new_dict.into_any().unbind())
}

/// Clone `payload` with one attribute replaced.  Prefers Pydantic `model_copy`
/// so that field validation is respected; falls back to `copy.copy` + `setattr`.
fn clone_payload(
    py: Python<'_>,
    payload: &Bound<'_, PyAny>,
    attr: &str,
    new_value: &Py<PyAny>,
) -> PyResult<Py<PyAny>> {
    if payload.hasattr("model_copy")? {
        let update = PyDict::new(py);
        update.set_item(attr, new_value.bind(py))?;
        let kwargs = PyDict::new(py);
        kwargs.set_item("update", &update)?;
        Ok(payload
            .call_method("model_copy", (), Some(&kwargs))?
            .unbind())
    } else {
        let copy_mod = PyModule::import(py, "copy")?;
        let cloned = copy_mod.getattr("copy")?.call1((payload,))?;
        cloned.setattr(attr, new_value.bind(py))?;
        Ok(cloned.unbind())
    }
}

/// Emit a WARNING-level log line listing the detected issues.
fn log_violation(py: Python<'_>, stage: &str, issues: &[String]) -> PyResult<()> {
    let logging = PyModule::import(py, "logging")?;
    let logger = logging.getattr("getLogger")?.call1((LOGGER_NAME,))?;
    let msg = format!(
        "SQL-SANITIZER [{}] blocked — issues: {}",
        stage,
        issues.join(", ")
    );
    logger.call_method1("warning", (msg,))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use pyo3::ffi::c_str;
    use pyo3::prelude::*;
    use pyo3::types::{PyDict, PyModule};

    fn install_fake_framework(py: Python<'_>) -> PyResult<()> {
        let framework = PyModule::from_code(
            py,
            c_str!(
                r#"
class PromptPrehookResult:
    def __init__(self, continue_processing=True, violation=None, modified_payload=None, metadata=None):
        self.continue_processing = continue_processing
        self.violation = violation
        self.modified_payload = modified_payload
        self.metadata = metadata or {}

class ToolPreInvokeResult:
    def __init__(self, continue_processing=True, violation=None, modified_payload=None, metadata=None):
        self.continue_processing = continue_processing
        self.violation = violation
        self.modified_payload = modified_payload
        self.metadata = metadata or {}

class PluginViolation:
    def __init__(self, reason=None, description=None, code=None, details=None):
        self.reason = reason
        self.description = description
        self.code = code
        self.details = details or {}
"#
            ),
            c_str!("framework.py"),
            c_str!("cpex.framework"),
        )?;
        let cpex = PyModule::from_code(py, c_str!(""), c_str!("cpex.py"), c_str!("cpex"))?;
        cpex.setattr("framework", &framework)?;
        let sys = PyModule::import(py, "sys")?;
        let modules = sys.getattr("modules")?;
        modules.set_item("cpex", &cpex)?;
        modules.set_item("cpex.framework", &framework)?;
        Ok(())
    }

    /// Build a minimal fake payload: `SimpleNamespace(args=args_dict, name="test", prompt_id="p")`.
    fn make_payload<'py>(
        py: Python<'py>,
        args: &Bound<'py, PyDict>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let types_mod = PyModule::import(py, "types")?;
        let ns_cls = types_mod.getattr("SimpleNamespace")?;
        let kw = PyDict::new(py);
        kw.set_item("args", args)?;
        kw.set_item("name", "test_tool")?;
        kw.set_item("prompt_id", "test_prompt")?;
        ns_cls.call((), Some(&kw))
    }

    #[test]
    fn blocks_unsafe_delete() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            install_fake_framework(py).unwrap();
            let empty = PyDict::new(py);
            let core = super::SqlSanitizerPluginCore::new(empty.as_any()).unwrap();
            let args = PyDict::new(py);
            args.set_item("sql", "DELETE FROM users").unwrap();
            let payload = make_payload(py, &args).unwrap();
            let none_val = py.None().into_bound(py);
            let result = core
                .prompt_pre_fetch(py, &payload, &none_val, None)
                .unwrap();
            let cp: bool = result
                .bind(py)
                .getattr("continue_processing")
                .unwrap()
                .extract()
                .unwrap();
            assert!(!cp, "DELETE without WHERE must be blocked");
        });
    }

    #[test]
    fn allows_safe_select() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            install_fake_framework(py).unwrap();
            let empty = PyDict::new(py);
            let core = super::SqlSanitizerPluginCore::new(empty.as_any()).unwrap();
            let args = PyDict::new(py);
            args.set_item("sql", "SELECT * FROM users WHERE id = 1")
                .unwrap();
            let payload = make_payload(py, &args).unwrap();
            let none_val = py.None().into_bound(py);
            let result = core.tool_pre_invoke(py, &payload, &none_val, None).unwrap();
            let cp: bool = result
                .bind(py)
                .getattr("continue_processing")
                .unwrap()
                .extract()
                .unwrap();
            assert!(cp, "Safe SELECT should be allowed");
        });
    }

    #[test]
    fn per_statement_fix_four_updates_all_blocked() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            install_fake_framework(py).unwrap();
            let empty = PyDict::new(py);
            let core = super::SqlSanitizerPluginCore::new(empty.as_any()).unwrap();
            // Four WHERE-less UPDATEs; final SELECT has WHERE — must still block
            let sql = "UPDATE a SET x=1; UPDATE b SET x=2; UPDATE c SET x=3; \
                       UPDATE d SET x=4; SELECT * FROM e WHERE id=1";
            let args = PyDict::new(py);
            args.set_item("query", sql).unwrap();
            let payload = make_payload(py, &args).unwrap();
            let none_val = py.None().into_bound(py);
            let result = core.tool_pre_invoke(py, &payload, &none_val, None).unwrap();
            let cp: bool = result
                .bind(py)
                .getattr("continue_processing")
                .unwrap()
                .extract()
                .unwrap();
            assert!(
                !cp,
                "WHERE-less UPDATEs must be blocked even when WHERE appears elsewhere"
            );
        });
    }

    /// SQL with a `--` comment → the comment is stripped → `modified_payload` is
    /// returned with the cleaned SQL.  Catches:
    ///   - `plugin.rs:136` (`!stripped.is_empty()` → `stripped.is_empty()`)
    ///   - `scanner.rs:55` (`clean != text` → `clean == text`)
    #[test]
    fn comment_stripping_returns_modified_payload() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            install_fake_framework(py).unwrap();
            let empty = PyDict::new(py);
            let core = super::SqlSanitizerPluginCore::new(empty.as_any()).unwrap();
            let args = PyDict::new(py);
            // Safe SQL but with a trailing comment — should be stripped
            args.set_item("sql", "SELECT 1 -- drop hint").unwrap();
            let payload = make_payload(py, &args).unwrap();
            let none_val = py.None().into_bound(py);
            let result = core.tool_pre_invoke(py, &payload, &none_val, None).unwrap();
            let bound = result.bind(py);
            let cp: bool = bound
                .getattr("continue_processing")
                .unwrap()
                .extract()
                .unwrap();
            assert!(cp, "safe SQL with comment should still be allowed");
            let mp = bound.getattr("modified_payload").unwrap();
            assert!(
                !mp.is_none(),
                "modified_payload must be set when comments are stripped"
            );
        });
    }

    /// Monitoring mode (`block_on_violation=false`) + SQL that both has issues
    /// AND contains a strippable comment → result must carry *both*
    /// `modified_payload` and `metadata.sql_issues`.
    ///
    /// Regression test for the bug where the modified-payload path returned
    /// early without populating `sql_issues`, silently losing audit information.
    #[test]
    fn monitoring_mode_with_comment_includes_sql_issues_in_metadata() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            install_fake_framework(py).unwrap();
            let cfg_dict = PyDict::new(py);
            cfg_dict.set_item("block_on_violation", false).unwrap();
            let core = super::SqlSanitizerPluginCore::new(cfg_dict.as_any()).unwrap();
            let args = PyDict::new(py);
            // Dangerous SQL with a comment: both stripping AND an issue occur
            args.set_item("sql", "DELETE FROM sessions -- cleanup")
                .unwrap();
            let payload = make_payload(py, &args).unwrap();
            let none_val = py.None().into_bound(py);
            let result = core.tool_pre_invoke(py, &payload, &none_val, None).unwrap();
            let bound = result.bind(py);
            let mp = bound.getattr("modified_payload").unwrap();
            assert!(
                !mp.is_none(),
                "modified_payload must be set (comment stripped)"
            );
            let metadata = bound.getattr("metadata").unwrap();
            let has_issues: bool = metadata
                .call_method1("__contains__", ("sql_issues",))
                .unwrap()
                .extract()
                .unwrap();
            assert!(
                has_issues,
                "sql_issues must be present in metadata even when comment stripping also occurred"
            );
        });
    }

    /// `block_on_violation=false` + dangerous SQL → pass-through with
    /// `metadata.sql_issues` populated.  Catches
    /// `plugin.rs:154` (`!issues.is_empty()` → `issues.is_empty()`).
    #[test]
    fn monitoring_mode_populates_sql_issues_metadata() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            install_fake_framework(py).unwrap();
            let cfg_dict = PyDict::new(py);
            cfg_dict.set_item("block_on_violation", false).unwrap();
            let core = super::SqlSanitizerPluginCore::new(cfg_dict.as_any()).unwrap();
            let args = PyDict::new(py);
            args.set_item("sql", "DELETE FROM sessions").unwrap();
            let payload = make_payload(py, &args).unwrap();
            let none_val = py.None().into_bound(py);
            let result = core.tool_pre_invoke(py, &payload, &none_val, None).unwrap();
            let bound = result.bind(py);
            let cp: bool = bound
                .getattr("continue_processing")
                .unwrap()
                .extract()
                .unwrap();
            assert!(cp, "monitoring mode must not block");
            let metadata = bound.getattr("metadata").unwrap();
            let has_key: bool = metadata
                .call_method1("__contains__", ("sql_issues",))
                .unwrap()
                .extract()
                .unwrap();
            assert!(
                has_key,
                "metadata.sql_issues must be set in monitoring mode"
            );
        });
    }

    /// `block_on_violation=false` + safe SQL → `metadata.sql_issues` must NOT
    /// be present.  Together with `monitoring_mode_populates_sql_issues_metadata`
    /// this brackets the `!issues.is_empty()` guard.
    #[test]
    fn monitoring_mode_safe_sql_has_no_issues_metadata() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            install_fake_framework(py).unwrap();
            let cfg_dict = PyDict::new(py);
            cfg_dict.set_item("block_on_violation", false).unwrap();
            let core = super::SqlSanitizerPluginCore::new(cfg_dict.as_any()).unwrap();
            let args = PyDict::new(py);
            args.set_item("sql", "SELECT 1").unwrap();
            let payload = make_payload(py, &args).unwrap();
            let none_val = py.None().into_bound(py);
            let result = core.tool_pre_invoke(py, &payload, &none_val, None).unwrap();
            let bound = result.bind(py);
            let metadata = bound.getattr("metadata").unwrap();
            // metadata should be an empty dict — no sql_issues key
            let has_key: bool = metadata
                .call_method1("__contains__", ("sql_issues",))
                .unwrap()
                .extract()
                .unwrap();
            assert!(!has_key, "safe SQL must not produce sql_issues metadata");
        });
    }

    /// `fields=["sql"]` + dangerous SQL in a *different* field → must be
    /// allowed.  Catches:
    ///   - `scanner.rs:46`  (`s == key` → `s != key`)
    ///   - `config.rs:86`   (`!val.is_none()` → `val.is_none()` for fields)
    #[test]
    fn field_filter_allows_violation_in_non_matching_field() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            install_fake_framework(py).unwrap();
            let cfg_dict = PyDict::new(py);
            cfg_dict.set_item("fields", vec!["sql"]).unwrap();
            let core = super::SqlSanitizerPluginCore::new(cfg_dict.as_any()).unwrap();
            let args = PyDict::new(py);
            // Dangerous SQL is in `query`, not in `sql` — must be ignored
            args.set_item("query", "DELETE FROM users").unwrap();
            args.set_item("sql", "SELECT 1").unwrap();
            let payload = make_payload(py, &args).unwrap();
            let none_val = py.None().into_bound(py);
            let result = core.tool_pre_invoke(py, &payload, &none_val, None).unwrap();
            let cp: bool = result
                .bind(py)
                .getattr("continue_processing")
                .unwrap()
                .extract()
                .unwrap();
            assert!(cp, "violation in non-matching field must be ignored");
        });
    }

    /// Custom `blocked_statements` pattern → SQL matching the pattern is
    /// blocked.  Catches `config.rs:94` (`!val.is_none()` → `val.is_none()`
    /// for blocked_statements).
    #[test]
    fn custom_blocked_pattern_blocks_matching_sql() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            install_fake_framework(py).unwrap();
            let cfg_dict = PyDict::new(py);
            // Replace default patterns with a custom one that blocks SELECT
            cfg_dict
                .set_item("blocked_statements", vec!["\\bSELECT\\b"])
                .unwrap();
            let core = super::SqlSanitizerPluginCore::new(cfg_dict.as_any()).unwrap();
            let args = PyDict::new(py);
            args.set_item("sql", "SELECT * FROM users").unwrap();
            let payload = make_payload(py, &args).unwrap();
            let none_val = py.None().into_bound(py);
            let result = core.tool_pre_invoke(py, &payload, &none_val, None).unwrap();
            let cp: bool = result
                .bind(py)
                .getattr("continue_processing")
                .unwrap()
                .extract()
                .unwrap();
            assert!(!cp, "SQL matching a custom blocked pattern must be blocked");
        });
    }

    /// `fields=["sql"]` + dangerous SQL in a list value under a *different*
    /// field → must be allowed.  Catches `scanner.rs:78`
    /// (`s == key` → `s != key` for list string items).
    #[test]
    fn field_filter_list_items_respect_field_filter() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            install_fake_framework(py).unwrap();
            let cfg_dict = PyDict::new(py);
            cfg_dict.set_item("fields", vec!["sql"]).unwrap();
            let core = super::SqlSanitizerPluginCore::new(cfg_dict.as_any()).unwrap();
            let args = PyDict::new(py);
            // List of strings under key `queries` (not in `fields`) — must be ignored
            let queries =
                pyo3::types::PyList::new(py, ["DELETE FROM users", "DROP TABLE t"]).unwrap();
            args.set_item("queries", &queries).unwrap();
            args.set_item("sql", "SELECT 1").unwrap();
            let payload = make_payload(py, &args).unwrap();
            let none_val = py.None().into_bound(py);
            let result = core.tool_pre_invoke(py, &payload, &none_val, None).unwrap();
            let cp: bool = result
                .bind(py)
                .getattr("continue_processing")
                .unwrap()
                .extract()
                .unwrap();
            assert!(
                cp,
                "violations in list items under non-matching field must be ignored"
            );
        });
    }
}
