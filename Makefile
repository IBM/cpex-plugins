.PHONY: help plugins-list plugins-validate plugin-test plugin-mutants plugin-mutants-list plugin-scaffold plugin-scaffold-help

help:
	@printf "plugins-list\nplugins-validate\nplugin-test PLUGIN=<slug>\nplugin-mutants PLUGIN=<slug>\nplugin-mutants-list PLUGIN=<slug>\nplugin-scaffold\nplugin-scaffold-help\n"

plugins-list:
	@python3 tools/plugin_catalog.py list .

plugins-validate:
	@python3 tools/plugin_catalog.py validate .
	@python3 -m unittest tests/test_plugin_catalog.py tests/test_install_built_wheel.py

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
