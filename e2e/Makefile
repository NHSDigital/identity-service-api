SHELL := /bin/bash
########################################################################################################################
##
## app e2e tests
##
########################################################################################################################
pwd := ${PWD}
dirname := $(notdir $(patsubst %/,%,$(CURDIR)))
activate = poetry run

list:
	@grep '^[^#[:space:]].*:' Makefile

guard-%:
	@ if [ "${${*}}" = "" ]; then \
		echo "Environment variable $* not set"; \
		exit 1; \
	fi


test:
	$(activate) pytest

e2e:
	rm -f ../reports/e2e.xml  > /dev/null || true
	$(activate) python -m coverage run --source ./ --module pytest --reruns 10  -rxs -v --junit-xml=../reports/e2e.xml --ignore .venv || true
	@if [[ ! -f ../reports/e2e.xml ]]; then echo report not created; exit 1; fi

smoketest:
	rm -f ../reports/smoketest.xml  > /dev/null || true
	$(activate) coverage run --source ./ --module pytest -m smoketest -rxs -v --junit-xml=../reports/smoketest.xml --ignore .venv || true
	@if [[ ! -f ../reports/smoketest.xml ]]; then echo report not created; exit 1; fi

test_keycloak:
	env OAUTH_BASE_URI='https://internal-dev.api.service.nhs.uk' \
		OAUTH_PROXY='oauth2-int-pr-253' \
		JWT_PRIVATE_KEY_ABSOLUTE_PATH='/home/jf/Work/NHSDigital/utils-snippets/key.txt' \
		APIGEE_API_TOKEN=`env SSO_LOGIN_URL='https://login.apigee.com' get_token -u josh.finch1@nhs.net` \
		HELLO_WORLD_API_URL='https://internal-dev.api.service.nhs.uk/hello-world/hello/user' \
		ID_TOKEN_PRIVATE_KEY_ABSOLUTE_PATH='/home/jf/Work/NHSDigital/utils-snippets/idTokenKey.txt' \
		ID_TOKEN_NHS_LOGIN_PRIVATE_KEY_ABSOLUTE_PATH='/home/jf/Work/NHSDigital/identity-service-jwks/scripts/nhsLoginTestRS512.key' \
		$(activate) pytest
