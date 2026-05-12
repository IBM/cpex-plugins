from importlib.resources import files

import yaml


def test_manifest_declares_tool_pre_invoke_hook():
    manifest = yaml.safe_load(
        files("cpex_secrets_detection")
        .joinpath("plugin-manifest.yaml")
        .read_text(encoding="utf-8")
    )

    assert "tool_pre_invoke" in manifest["available_hooks"]
