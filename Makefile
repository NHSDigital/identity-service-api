SHELL=/bin/bash -euo pipefail

install: install-node install-python

install-python:
	poetry install

install-node:
	npm install

test:
	@echo "No tests configured."

lint:
	npm run lint
	poetry run flake8 **/*.py
	find -name '*.sh' | grep -v node_modules | xargs shellcheck

clean:
	rm -rf build
	rm -rf dist

publish: clean
	mkdir -p build
	npm run publish 2> /dev/null

serve: update-examples
	npm run serve

check-licenses:
	npm run check-licenses
	scripts/check_python_licenses.sh

deploy-proxy: update-examples
	scripts/deploy_proxy.sh

deploy-spec: update-examples
	scripts/deploy_spec.sh

format:
	poetry run black **/*.py

build-proxy:
	scripts/build_proxy.sh

_dist_include="pytest.ini poetry.lock poetry.toml pyproject.toml Makefile build/. e2e"

release: clean publish build-proxy
	mkdir -p dist
	for f in $(_dist_include); do cp -r $$f dist; done

.PHONY: e2e
# e2e:
# 	rm -f reports/e2e.xml  > /dev/null || true
# 	cd e2e && poetry run python -m pytest -n auto --reruns 5 --reruns-delay 2 -rxs -v -m "not mock_auth" --junit-xml=../reports/e2e.xml --ignore .venv || true
# 	@if [[ ! -f reports/e2e.xml ]]; then echo report not created; exit 1; fi

# e2e-mock:
# 	rm -f reports/e2e.xml  > /dev/null || true
# 	cd e2e && poetry run python -m pytest -n auto --reruns 5 --reruns-delay 2 -rxs -v -m "not simulated_auth" --junit-xml=../reports/e2e.xml --ignore .venv || true
# 	@if [[ ! -f reports/e2e.xml ]]; then echo report not created; exit 1; fi


# Test
e2e:
	rm -f reports/e2e.xml  > /dev/null || true 
	@for f in  $$(find  e2e/tests  -name "test_*.py") ; do \
		echo $$f; \
		PYTEST_ADDOPTS="--color=yes" poetry run pytest --reruns 5 --reruns-delay 2 $$f -m "not mock_auth" || true; \
	done

e2e-mock:
	rm -f reports/e2e.xml  > /dev/null || true 
	@for f in  $$(find  e2e/tests  -name "test_*.py") ; do \
		echo $$f; \
		PYTEST_ADDOPTS="--color=yes" poetry run pytest --reruns 5 --reruns-delay 2 $$f -m "not simulated_auth" || true; \
	done

# poetry run python -m pytest -n auto --reruns 5 --reruns-delay 2 $$f  -m "not simulated_auth" --junit-xml=../reports/e2e.xml --ignore .venv || true; \