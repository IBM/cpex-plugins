import subprocess
import sys
from pathlib import Path

from real_cpex_imports import assert_real_cpex_imports
from secrets_detection.helpers import *  # noqa: F403,F405


def test_imports_with_real_cpex_package() -> None:
    plugin_root = (
        Path(__file__).resolve().parents[3]
        / "plugins"
        / "rust"
        / "python-package"
        / "secrets_detection"
    )
    assert_real_cpex_imports(
        plugin_root,
        [
            "from cpex_secrets_detection.secrets_detection import SecretsDetectionPlugin",
        ],
    )


class TestPublicRustApi:
    def test_scan_container_preserves_tuple_shape_when_clean(self):
        payload = ("safe", 1, {"nested": "value"})

        count, redacted, findings = py_scan_container(
            payload, {"redact": True, "redaction_text": "[REDACTED]"}
        )

        assert count == 0
        assert findings == []
        assert redacted == payload
        assert isinstance(redacted, tuple)

    def test_scan_container_handles_split_concerns_through_public_api(self):
        class Wrapper:
            def __init__(self, value, back=None):
                self.value = value
                self.back = back

            def model_dump(self):
                return {"value": "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE", "back": self.back}

        back_edge = Wrapper("safe")
        payload = ("safe", back_edge)
        back_edge.back = payload

        count, redacted, findings = py_scan_container(
            payload, {"redact": True, "redaction_text": "[REDACTED]"}
        )

        assert count == 1
        assert findings == [{"type": "aws_access_key_id"}]
        assert isinstance(redacted, tuple)
        assert redacted[0] == "safe"
        assert isinstance(redacted[1], Wrapper)
        assert redacted[1].value == "AWS_ACCESS_KEY_ID=[REDACTED]"
        assert redacted[1] is not back_edge
        assert redacted[1].back is redacted
        assert back_edge.value == "safe"
        assert back_edge.back is payload

    def test_scan_container_preserves_opaque_object_when_clean(self):
        class SlotOnlyPayload:
            __slots__ = ("value",)

            def __init__(self, value):
                self.value = value

        payload = SlotOnlyPayload("safe")

        count, redacted, findings = py_scan_container(
            payload, {"redact": True, "redaction_text": "[REDACTED]"}
        )

        assert count == 0
        assert findings == []
        assert redacted is payload

    def test_scan_container_redacts_custom_object_with_dict_state(self):
        class SecretBox:
            def __init__(self, value):
                self.value = value

        payload = SecretBox("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE")

        count, redacted, findings = py_scan_container(
            payload, {"redact": True, "redaction_text": "[REDACTED]"}
        )

        assert count == 1
        assert findings == [{"type": "aws_access_key_id"}]
        assert redacted is not payload
        assert isinstance(redacted, SecretBox)
        assert redacted.value == "AWS_ACCESS_KEY_ID=[REDACTED]"
        assert payload.value == "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"

    def test_scan_container_scans_string_attrs_when_dict_has_non_string_key(self):
        class BadKey:
            pass

        class SecretBox:
            def __init__(self):
                self.value = "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"
                self.__dict__[BadKey()] = "side-channel"

        payload = SecretBox()

        count, redacted, findings = py_scan_container(
            payload, {"redact": True, "redaction_text": "[REDACTED]"}
        )

        assert count == 1
        assert findings == [{"type": "aws_access_key_id"}]
        assert redacted is not payload
        assert isinstance(redacted, SecretBox)
        assert redacted.value == "AWS_ACCESS_KEY_ID=[REDACTED]"
        assert payload.value == "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"

    def test_scan_container_scans_non_string_dict_key_values_on_objects(self):
        class BadKey:
            pass

        class SecretBox:
            def __init__(self):
                self.value = "clean"
                self.__dict__[BadKey()] = "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"

        payload = SecretBox()

        count, redacted, findings = py_scan_container(
            payload, {"redact": True, "redaction_text": "[REDACTED]"}
        )

        assert count == 1
        assert findings == [{"type": "aws_access_key_id"}]
        assert redacted is not payload
        assert isinstance(redacted, SecretBox)
        assert redacted.value == "clean"
        assert payload.value == "clean"
        assert any(
            value == "AWS_ACCESS_KEY_ID=[REDACTED]"
            for key, value in redacted.__dict__.items()
            if not isinstance(key, str)
        )
        assert any(
            value == "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"
            for key, value in payload.__dict__.items()
            if not isinstance(key, str)
        )

    def test_scan_container_redacts_mixed_string_and_non_string_dict_values(self):
        class BadKey:
            pass

        class SecretBox:
            def __init__(self):
                self.value = "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"
                self.__dict__[BadKey()] = (
                    "AWS_SECRET_ACCESS_KEY=FAKESecretAccessKeyForTestingEXAMPLE0000"
                )

        payload = SecretBox()

        count, redacted, findings = py_scan_container(
            payload, {"redact": True, "redaction_text": "[REDACTED]"}
        )

        assert count == 2
        assert findings == [
            {"type": "aws_access_key_id"},
            {"type": "aws_secret_access_key"},
        ]
        assert redacted is not payload
        assert isinstance(redacted, SecretBox)
        assert redacted.value == "AWS_ACCESS_KEY_ID=[REDACTED]"
        assert any(
            value == "[REDACTED]"
            for key, value in redacted.__dict__.items()
            if not isinstance(key, str)
        )
        assert payload.value == "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"

    def test_scan_container_preserves_clean_non_string_dict_values_when_rebuilt(self):
        class BadKey:
            pass

        class SecretBox:
            def __init__(self):
                self.value = "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"
                self.__dict__[BadKey()] = "side-channel"

        payload = SecretBox()

        count, redacted, findings = py_scan_container(
            payload, {"redact": True, "redaction_text": "[REDACTED]"}
        )

        assert count == 1
        assert findings == [{"type": "aws_access_key_id"}]
        assert redacted is not payload
        assert isinstance(redacted, SecretBox)
        assert redacted.value == "AWS_ACCESS_KEY_ID=[REDACTED]"
        assert any(
            value == "side-channel"
            for key, value in redacted.__dict__.items()
            if not isinstance(key, str)
        )

    def test_scan_container_returns_original_for_clean_non_string_dict_values(self):
        class BadKey:
            pass

        class SecretBox:
            def __init__(self):
                self.__dict__[BadKey()] = "side-channel"

        payload = SecretBox()

        count, redacted, findings = py_scan_container(
            payload, {"redact": True, "redaction_text": "[REDACTED]"}
        )

        assert count == 0
        assert findings == []
        assert redacted is payload
        assert any(
            value == "side-channel"
            for key, value in redacted.__dict__.items()
            if not isinstance(key, str)
        )

    def test_scan_container_preserves_clean_non_string_dict_values_after_model_dump_redaction(self):
        class BadKey:
            pass

        class SecretBox:
            def __init__(self):
                self.value = "clean"
                self.__dict__[BadKey()] = "side-channel"
                self.__dict__[BadKey()] = self

            def model_dump(self):
                return {"value": "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"}

        payload = SecretBox()

        count, redacted, findings = py_scan_container(
            payload, {"redact": True, "redaction_text": "[REDACTED]"}
        )

        assert count == 1
        assert findings == [{"type": "aws_access_key_id"}]
        assert redacted is not payload
        assert isinstance(redacted, SecretBox)
        assert redacted.value == "AWS_ACCESS_KEY_ID=[REDACTED]"
        assert any(
            value == "side-channel"
            for key, value in redacted.__dict__.items()
            if not isinstance(key, str)
        )
        assert any(
            value is redacted
            for key, value in redacted.__dict__.items()
            if not isinstance(key, str)
        )

    def test_scan_container_does_not_apply_clean_dict_values_to_different_serialized_object_type(self):
        class BadKey:
            pass

        class View:
            def __init__(self):
                self.secret = "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"

        class SecretBox:
            def __init__(self):
                self.__dict__[BadKey()] = "side-channel"

            def model_dump(self):
                return View()

        payload = SecretBox()

        count, redacted, findings = py_scan_container(
            payload, {"redact": True, "redaction_text": "[REDACTED]"}
        )

        assert count == 1
        assert findings == [{"type": "aws_access_key_id"}]
        assert isinstance(redacted, View)
        assert redacted.secret == "AWS_ACCESS_KEY_ID=[REDACTED]"
        assert not any(
            value == "side-channel"
            for key, value in redacted.__dict__.items()
            if not isinstance(key, str)
        )

    def test_scan_container_rewrites_non_string_dict_back_edges_on_objects(self):
        class BadKey:
            pass

        class SecretBox:
            def __init__(self):
                self.__dict__[BadKey()] = "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"
                self.__dict__[BadKey()] = self

        payload = SecretBox()

        count, redacted, findings = py_scan_container(
            payload, {"redact": True, "redaction_text": "[REDACTED]"}
        )

        assert count == 1
        assert findings == [{"type": "aws_access_key_id"}]
        assert redacted is not payload
        assert isinstance(redacted, SecretBox)
        assert any(
            value == "AWS_ACCESS_KEY_ID=[REDACTED]"
            for key, value in redacted.__dict__.items()
            if not isinstance(key, str) and isinstance(value, str)
        )
        assert any(
            value is redacted
            for key, value in redacted.__dict__.items()
            if not isinstance(key, str)
        )

    def test_scan_container_omits_match_previews_from_public_findings(self):
        count, _, findings = py_scan_container(
            "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE",
            {"redact": True, "redaction_text": "[REDACTED]"},
        )

        assert count == 1
        assert findings == [{"type": "aws_access_key_id"}]

    def test_scan_container_prefers_redacted_serialized_view_when_both_paths_match(self):
        class DualSurfacePayload:
            def __init__(self):
                self.state_secret = "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"

            def model_dump(self):
                return "AWS_SECRET_ACCESS_KEY=FAKESecretAccessKeyForTestingEXAMPLE0000"

        payload = DualSurfacePayload()

        count, redacted, findings = py_scan_container(
            payload, {"redact": True, "redaction_text": "[REDACTED]"}
        )

        assert count == 2
        assert findings == [
            {"type": "aws_access_key_id"},
            {"type": "aws_secret_access_key"},
        ]
        assert redacted == "[REDACTED]"

    def test_scan_container_redacts_non_replayable_custom_object(self):
        class NonReplayableBox:
            def __init__(self, secret):
                self.secret = secret
                self.derived = "derived"

        payload = NonReplayableBox("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE")

        count, redacted, findings = py_scan_container(
            payload, {"redact": True, "redaction_text": "[REDACTED]"}
        )

        assert count == 1
        assert len(findings) == 1
        assert redacted is not payload
        assert isinstance(redacted, NonReplayableBox)
        assert redacted.secret == "AWS_ACCESS_KEY_ID=[REDACTED]"
        assert redacted.derived == "derived"
        assert payload.secret == "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"

    def test_scan_container_redacts_slot_backed_custom_object(self):
        class SlotSecretBox:
            __slots__ = ("value",)

            def __init__(self, value):
                self.value = value

        payload = SlotSecretBox("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE")

        count, redacted, findings = py_scan_container(
            payload, {"redact": True, "redaction_text": "[REDACTED]"}
        )

        assert count == 1
        assert len(findings) == 1
        assert redacted is not payload
        assert isinstance(redacted, SlotSecretBox)
        assert redacted.value == "AWS_ACCESS_KEY_ID=[REDACTED]"
        assert payload.value == "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"

    def test_scan_container_redacts_hybrid_dict_and_slots_object(self):
        class HybridSecretBox:
            __slots__ = {"slot_secret": "slot", "__dict__": "dict"}

            def __init__(self, slot_secret, label):
                self.slot_secret = slot_secret
                self.label = label

        payload = HybridSecretBox(
            "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE",
            "safe",
        )

        count, redacted, findings = py_scan_container(
            payload, {"redact": True, "redaction_text": "[REDACTED]"}
        )

        assert count == 1
        assert len(findings) == 1
        assert redacted is not payload
        assert isinstance(redacted, HybridSecretBox)
        assert redacted.slot_secret == "AWS_ACCESS_KEY_ID=[REDACTED]"
        assert redacted.label == "safe"
        assert payload.slot_secret == "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"

    def test_scan_container_redacts_guarded_object_without_running_setattr(self):
        class GuardedSecretBox:
            __slots__ = ("secret", "label", "_locked")

            def __init__(self, secret, label):
                object.__setattr__(self, "secret", secret)
                object.__setattr__(self, "label", label)
                object.__setattr__(self, "_locked", True)

            def __setattr__(self, name, value):
                raise AssertionError(f"unexpected setattr for {name}")
                object.__setattr__(self, name, value)

        payload = GuardedSecretBox(
            "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE",
            "safe",
        )

        count, redacted, findings = py_scan_container(
            payload, {"redact": True, "redaction_text": "[REDACTED]"}
        )

        assert count == 1
        assert len(findings) == 1
        assert redacted is not payload
        assert isinstance(redacted, GuardedSecretBox)
        assert redacted.secret == "AWS_ACCESS_KEY_ID=[REDACTED]"
        assert redacted.label == "safe"
        assert payload.secret == "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"

    def test_scan_container_redacts_slots_declared_as_mapping(self):
        class MappingSlotSecretBox:
            __slots__ = {"secret": "slot doc"}

            def __init__(self, secret):
                self.secret = secret

        payload = MappingSlotSecretBox("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE")

        count, redacted, findings = py_scan_container(
            payload, {"redact": True, "redaction_text": "[REDACTED]"}
        )

        assert count == 1
        assert len(findings) == 1
        assert redacted is not payload
        assert isinstance(redacted, MappingSlotSecretBox)
        assert redacted.secret == "AWS_ACCESS_KEY_ID=[REDACTED]"
        assert payload.secret == "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"

    def test_scan_container_detects_secret_exposed_only_by_model_dump(self):
        class SplitSecretModel(BaseModel):
            prefix: str
            suffix: str

            @model_serializer(mode="plain")
            def serialize_model(self):
                return f"{self.prefix}{self.suffix}"

        payload = SplitSecretModel(prefix="AKIA", suffix="FAKE12345EXAMPLE")

        count, redacted, findings = py_scan_container(
            payload, {"redact": True, "redaction_text": "[REDACTED]"}
        )

        assert count == 1
        assert len(findings) == 1
        assert redacted == "[REDACTED]"

    def test_scan_container_detects_secret_when_model_dump_key_overlaps_internal_state(self):
        class OverlappingStateBox:
            def __init__(self):
                self.secret = "safe"

            def model_dump(self):
                return {"secret": "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"}

        payload = OverlappingStateBox()

        count, redacted, findings = py_scan_container(
            payload, {"redact": True, "redaction_text": "[REDACTED]"}
        )

        assert count == 1
        assert len(findings) == 1
        assert isinstance(redacted, OverlappingStateBox)
        assert redacted.secret == "AWS_ACCESS_KEY_ID=[REDACTED]"
        assert payload.secret == "safe"

    def test_scan_container_redacts_secret_exposed_only_by_root_model_dump(self):
        payload = RootModel[str]("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE")

        count, redacted, findings = py_scan_container(
            payload, {"redact": True, "redaction_text": "[REDACTED]"}
        )

        assert count == 1
        assert len(findings) == 1
        assert isinstance(redacted, RootModel)
        assert redacted.root == "AWS_ACCESS_KEY_ID=[REDACTED]"

    def test_scan_container_handles_recursive_model_dump_without_crashing(self):
        script = """
from cpex_secrets_detection.secrets_detection_rust import py_scan_container

class RecursivePayload:
    def __init__(self):
        self.secret = "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"

    def model_dump(self):
        return self

count, redacted, findings = py_scan_container(
    RecursivePayload(),
    {"redact": True, "redaction_text": "[REDACTED]"},
)
assert count == 1
assert len(findings) == 1
assert redacted.secret == "AWS_ACCESS_KEY_ID=[REDACTED]"
"""
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )

        assert result.returncode == 0, result.stderr or result.stdout

    def test_scan_container_redacts_cyclic_dict_without_leaking_original_back_edge(self):
        payload = {}
        payload["secret"] = "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"
        payload["self"] = payload

        count, redacted, findings = py_scan_container(
            payload, {"redact": True, "redaction_text": "[REDACTED]"}
        )

        assert count == 1
        assert len(findings) == 1
        assert redacted["secret"] == "AWS_ACCESS_KEY_ID=[REDACTED]"
        assert redacted["self"] is redacted
        assert redacted["self"]["secret"] == "AWS_ACCESS_KEY_ID=[REDACTED]"

    def test_scan_container_redacts_self_referential_object_without_leaking_back_edge(self):
        class SelfReferentialBox:
            def __init__(self, secret):
                self.secret = secret
                self.self_ref = self

        payload = SelfReferentialBox("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE")

        count, redacted, findings = py_scan_container(
            payload, {"redact": True, "redaction_text": "[REDACTED]"}
        )

        assert count == 1
        assert len(findings) == 1
        assert redacted is not payload
        assert redacted.secret == "AWS_ACCESS_KEY_ID=[REDACTED]"
        assert redacted.self_ref is redacted
        assert redacted.self_ref.secret == "AWS_ACCESS_KEY_ID=[REDACTED]"

    def test_scan_container_redacts_tuple_cycle_without_leaking_original_back_edge(self):
        back_edge = []
        payload = ("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE", back_edge)
        back_edge.append(payload)

        count, redacted, findings = py_scan_container(
            payload, {"redact": True, "redaction_text": "[REDACTED]"}
        )

        assert count == 1
        assert len(findings) == 1
        assert isinstance(redacted, tuple)
        assert redacted[0] == "AWS_ACCESS_KEY_ID=[REDACTED]"
        assert redacted[1][0] is redacted
        assert redacted[1][0][0] == "AWS_ACCESS_KEY_ID=[REDACTED]"

    def test_scan_container_handles_recursive_model_dump_wrapper_without_crashing(self):
        script = """
from cpex_secrets_detection.secrets_detection_rust import py_scan_container

class WrapperPayload:
    def __init__(self, value):
        self.value = value

    def model_dump(self):
        return WrapperPayload(self.value)

count, redacted, findings = py_scan_container(
    WrapperPayload("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"),
    {"redact": True, "redaction_text": "[REDACTED]"},
)
assert count == 1
assert len(findings) == 1
assert redacted.value == "AWS_ACCESS_KEY_ID=[REDACTED]"
"""
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )

        assert result.returncode == 0, result.stderr or result.stdout

    def test_scan_container_detects_secret_exposed_only_by_serialized_wrapper_object(self):
        class View:
            def __init__(self, secret):
                self.secret = secret

        class WrappedSerializerModel(BaseModel):
            safe: str

            @model_serializer(mode="plain")
            def serialize_model(self):
                return View("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE")

        payload = WrappedSerializerModel(safe="ok")

        count, redacted, findings = py_scan_container(
            payload, {"redact": True, "redaction_text": "[REDACTED]"}
        )

        assert count == 1
        assert len(findings) == 1
        assert isinstance(redacted, View)
        assert redacted.secret == "AWS_ACCESS_KEY_ID=[REDACTED]"

    def test_scan_container_redacts_self_referential_model_copy_object_without_leak(self):
        class SelfReferentialModel(BaseModel):
            secret: str
            self_ref: "SelfReferentialModel | None" = None

        payload = SelfReferentialModel(secret="AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE")
        object.__setattr__(payload, "self_ref", payload)

        count, redacted, findings = py_scan_container(
            payload, {"redact": True, "redaction_text": "[REDACTED]"}
        )

        assert count == 1
        assert len(findings) == 1
        assert redacted is not payload
        assert isinstance(redacted, SelfReferentialModel)
        assert redacted.secret == "AWS_ACCESS_KEY_ID=[REDACTED]"
        assert redacted.self_ref is redacted
        assert redacted.self_ref.secret == "AWS_ACCESS_KEY_ID=[REDACTED]"
        assert payload.secret == "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"
        assert payload.self_ref is payload

    def test_scan_container_does_not_call_model_copy_on_clean_object(self):
        class CountingModel(BaseModel):
            value: str
            copies: int = 0

            def model_copy(self, *, update=None, deep=False):
                object.__setattr__(self, "copies", self.copies + 1)
                return super().model_copy(update=update, deep=deep)

        payload = CountingModel(value="clean")

        count, redacted, findings = py_scan_container(
            payload, {"redact": True, "redaction_text": "[REDACTED]"}
        )

        assert count == 0
        assert findings == []
        assert redacted is payload
        assert payload.copies == 0

    def test_scan_container_detects_secret_exposed_only_by_same_type_serialized_wrapper(self):
        class SameTypeWrapper(BaseModel):
            safe: str

            @model_serializer(mode="plain")
            def serialize_model(self):
                return SameTypeWrapper.model_construct(
                    safe="AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"
                )

        payload = SameTypeWrapper(safe="clean")

        count, redacted, findings = py_scan_container(
            payload, {"redact": True, "redaction_text": "[REDACTED]"}
        )

        assert count == 1
        assert len(findings) == 1
        assert isinstance(redacted, SameTypeWrapper)
        assert redacted.safe == "AWS_ACCESS_KEY_ID=[REDACTED]"
        assert payload.safe == "clean"

    def test_scan_container_redacts_same_type_serialized_wrapper_without_model_copy(self):
        class Wrapper:
            def __init__(self, value):
                self.value = value

            def model_dump(self):
                return Wrapper("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE")

        payload = Wrapper("clean")

        count, redacted, findings = py_scan_container(
            payload, {"redact": True, "redaction_text": "[REDACTED]"}
        )

        assert count == 1
        assert len(findings) == 1
        assert isinstance(redacted, Wrapper)
        assert redacted.value == "AWS_ACCESS_KEY_ID=[REDACTED]"
        assert payload.value == "clean"

    def test_scan_container_detects_nested_same_type_model_dump_only_secret(self):
        class Wrapper:
            def __init__(self, value, nested=False):
                self.value = value
                self.nested = nested

            def model_dump(self):
                if self.nested:
                    return "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"
                return Wrapper("clean", nested=True)

        payload = Wrapper("clean")

        count, redacted, findings = py_scan_container(
            payload, {"redact": True, "redaction_text": "[REDACTED]"}
        )

        assert count == 1
        assert findings == [{"type": "aws_access_key_id"}]
        assert redacted == "AWS_ACCESS_KEY_ID=[REDACTED]"
        assert payload.value == "clean"

    def test_scan_container_handles_recursive_same_type_wrapper_without_rebuild_state(self):
        script = """
from cpex_secrets_detection.secrets_detection_rust import py_scan_container

class Wrapper:
    __slots__ = ()

    def model_dump(self):
        return Wrapper()

count, redacted, findings = py_scan_container(
    Wrapper(),
    {"redact": True, "redaction_text": "[REDACTED]"},
)
assert count == 0
assert findings == []
assert isinstance(redacted, Wrapper)
"""
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )

        assert result.returncode == 0, result.stderr or result.stdout

    def test_scan_container_handles_tuple_rewrite_with_cyclic_dict_subgraph(self):
        script = """
from cpex_secrets_detection.secrets_detection_rust import py_scan_container

d = {}
payload = ("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE", d)
d["self"] = d

count, redacted, findings = py_scan_container(
    payload,
    {"redact": True, "redaction_text": "[REDACTED]"},
)
assert count == 1
assert redacted[0] == "AWS_ACCESS_KEY_ID=[REDACTED]"
assert redacted[1]["self"] is redacted[1]
"""
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )

        assert result.returncode == 0, result.stderr or result.stdout

    def test_scan_container_rewrites_tuple_cycle_references_inside_custom_objects(self):
        class Box:
            def __init__(self, back):
                self.back = back

        back_edge = Box(None)
        payload = ("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE", back_edge)
        back_edge.back = payload

        count, redacted, findings = py_scan_container(
            payload, {"redact": True, "redaction_text": "[REDACTED]"}
        )

        assert count == 1
        assert len(findings) == 1
        assert isinstance(redacted, tuple)
        assert isinstance(redacted[1], Box)
        assert redacted[0] == "AWS_ACCESS_KEY_ID=[REDACTED]"
        assert redacted[1].back is redacted
        assert redacted[1].back[0] == "AWS_ACCESS_KEY_ID=[REDACTED]"

    def test_scan_container_redacts_slots_declared_as_custom_iterable(self):
        class SlotNames:
            def __iter__(self):
                return iter(("secret",))

        class IterableSlotSecretBox:
            __slots__ = SlotNames()

            def __init__(self, secret):
                self.secret = secret

        payload = IterableSlotSecretBox("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE")

        count, redacted, findings = py_scan_container(
            payload, {"redact": True, "redaction_text": "[REDACTED]"}
        )

        assert count == 1
        assert len(findings) == 1
        assert isinstance(redacted, IterableSlotSecretBox)
        assert redacted.secret == "AWS_ACCESS_KEY_ID=[REDACTED]"
