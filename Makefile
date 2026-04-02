.PHONY: help plugins-list plugins-validate plugin-test

help:
	@printf "plugins-list\nplugins-validate\nplugin-test PLUGIN=<slug>\n"

plugins-list:
	@python3 tools/plugin_catalog.py list .

plugins-validate:
	@python3 tools/plugin_catalog.py validate .
	@python3 -m unittest tests/test_plugin_catalog.py tests/test_install_built_wheel.py

plugin-test:
	@test -n "$(PLUGIN)" || (echo "Set PLUGIN=<slug>" && exit 1)
	@cd plugins/rust/python-package/$(PLUGIN) && make sync && make ci
