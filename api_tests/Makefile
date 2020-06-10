BASE :=-f docker-compose.yml
DOCKER_TEST_DIR :=/var/api_tests
TEST_REPORT :=--junitxml=test_report.xml
.DEFAULT_GOAL := default


default : setup run save teardown

run :
	@echo "Executing all tests..."
	docker-compose $(BASE) run -T test_env pytest  -n auto -sq --tb=line --looponfail $(TEST_REPORT) $(DOCKER_TEST_DIR)/tests/

setup: build up

update: teardown setup

save :
	docker cp test_env:${DOCKER_TEST_DIR}/test_report.xml .

build :
	@echo "Building image..."
	docker-compose $(BASE) build

up :
	@echo "Starting up container..."
	docker-compose $(BASE) up -d

down :
	@echo "Removing container..."
	docker-compose $(BASE) down -v

restart :
	down
	up

teardown : down
	@echo "Deleting docker image..."
	docker rmi $$(docker images --format '{{.Repository}}:{{.Tag}}' | grep 'identity-service-api/test-env')

shell :
	docker exec -ti test_env bash

test-token-endpoint :
	@echo "Executing tests with the mark token_endpoint..."
	docker-compose $(BASE) run -T test_env pytest -m token_endpoint -sq --tb=line $(TEST_REPORT) $(DOCKER_TEST_DIR)/tests/

test-authorize-endpoint :
	@echo "Executing tests with the mark: authorize_endpoint..."
	docker-compose $(BASE) run -T test_env pytest -m authorize_endpoint -sq --tb=line $(TEST_REPORT) $(DOCKER_TEST_DIR)/tests/

test-error-conditions :
	@echo "Executing tests with the mark: errors..."
	docker-compose $(BASE) run -T test_env pytest -m errors -sq --tb=line $(TEST_REPORT) $(DOCKER_TEST_DIR)/tests/

test-happy-path :
	@echo "Executing tests with the mark: happy_path..."
	docker-compose $(BASE) run -T test_env pytest -m happy_path -sq --tb=line $(TEST_REPORT) $(DOCKER_TEST_DIR)/tests/

test :
ifdef id
	@echo "Executing test-id: " + $(id) + "..."
	docker-compose $(BASE) run -T test_env pytest -m apm_$(id) -sq --tb=line $(TEST_REPORT) $(DOCKER_TEST_DIR)/tests/
else ifdef mark
	@echo "Executing test cases with mark: " + $(mark) + "..."
	docker-compose $(BASE) run -T test_env pytest -m $(mark) -sq --tb=line $(TEST_REPORT) $(DOCKER_TEST_DIR)/tests/
else
	@echo 'Please specify a apm ticket or a pytest mark. eg: make test id=801 or make test mark="happy_path"'
endif
