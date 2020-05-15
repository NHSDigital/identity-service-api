BASE :=-f docker-compose.yml
DOCKER_TEST_DIR :=/var/api_tests
TEST_REPORT :=--junitxml=/var/api_tests/test_report.xml
.DEFAULT_GOAL := default


default : setup run

run :
	@echo "Executing all tests..."
	docker-compose $(BASE) run -T test_env pytest -sq --tb=line $(DOCKER_TEST_DIR)/tests/ $(TEST_REPORT)

setup: build up

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

test-token-endpoint :
	@echo "Executing tests with the mark token_endpoint..."
	docker-compose $(BASE) run -T test_env pytest -m token_endpoint -sq --tb=line $(DOCKER_TEST_DIR)/tests/ $(TEST_REPORT)

test-authorize-endpoint :
	@echo "Executing tests with the mark: authorize_endpoint..."
	docker-compose $(BASE) run -T test_env pytest -m authorize_endpoint -sq --tb=line $(DOCKER_TEST_DIR)/tests/ $(TEST_REPORT)

test-error-conditions :
	@echo "Executing tests with the mark: errors..."
	docker-compose $(BASE) run -T test_env pytest -m errors -sq --tb=line $(DOCKER_TEST_DIR)/tests/ $(TEST_REPORT)
