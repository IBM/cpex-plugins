DETECT_SECRETS_SPEC := git+https://github.com/ibm/detect-secrets.git@076672a9a01abdfc7ecee2e7d14f08cdccb73976

.PHONY: help plugins-list plugins-validate plugin-test plugin-mutants plugin-mutants-list plugin-scaffold plugin-scaffold-help detect-secrets-scan detect-secrets-audit detect-secrets-check

help:
	@printf "plugins-list\nplugins-validate\nplugin-test PLUGIN=<slug>\nplugin-mutants PLUGIN=<slug>\nplugin-mutants-list PLUGIN=<slug>\nplugin-scaffold\nplugin-scaffold-help\ndetect-secrets-scan\ndetect-secrets-audit\ndetect-secrets-check\n"

plugins-list:
	@python3 tools/plugin_catalog.py list .

plugins-validate:
	@python3 tools/plugin_catalog.py validate .
	@python3 -m unittest tests/test_plugin_catalog.py tests/test_install_built_wheel.py

detect-secrets-scan:  ## Regenerate secrets baseline
	@uv tool run $(DETECT_SECRETS_SPEC) scan \
		--update .secrets.baseline \
		--use-all-plugins

detect-secrets-audit:  ## Audit secrets baseline interactively
	@test -f .secrets.baseline || (echo "Run make detect-secrets-scan first" && exit 1)
	@uv tool run $(DETECT_SECRETS_SPEC) audit .secrets.baseline

detect-secrets-check:  ## Verify no unaudited secrets (CI equivalent)
	@pre-commit run detect-secrets --all-files

plugin-test:
	@test -n "$(PLUGIN)" || (echo "Set PLUGIN=<slug>" && exit 1)
	@cd plugins/rust/python-package/$(PLUGIN) && make sync && make ci

plugin-mutants:
	@test -n "$(PLUGIN)" || (echo "Set PLUGIN=<slug>" && exit 1)
	cargo mutants -p "$(PLUGIN)"

plugin-mutants-list:
	@test -n "$(PLUGIN)" || (echo "Set PLUGIN=<slug>" && exit 1)
	cargo mutants --list -p "$(PLUGIN)"

plugin-scaffold:
	@python3 -m pip install --quiet jinja2 2>/dev/null || pip install --quiet jinja2 2>/dev/null || true
	@python3 tools/scaffold_plugin.py

plugin-scaffold-help:
	@echo "Usage: make plugin-scaffold"
	@echo ""
	@echo "Interactively scaffold a new CPEX plugin with:"
	@echo "  - Rust + Python (PyO3/maturin) structure"
	@echo "  - Standard Makefile targets"
	@echo "  - Test scaffolding"
	@echo "  - Optional benchmark setup"
	@echo ""
	@echo "Non-interactive mode:"
	@echo "  python3 tools/scaffold_plugin.py --non-interactive --name my_plugin"
	@echo ""
	@echo "For more options:"
	@echo "  python3 tools/scaffold_plugin.py --help"
