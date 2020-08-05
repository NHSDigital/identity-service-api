
.PHONY: build up docker-login docker-push test test-greet

build:
	@docker build . -t 'dummy_api:1.0'

up: build
	@docker container run -p 80:80 -it 'dummy_api:1.0'

docker-login:
	@aws ecr get-login-password | docker login --username AWS --password-stdin  977715392814.dkr.ecr.eu-west-2.amazonaws.com

docker-push:
	@docker push 977715392814.dkr.ecr.eu-west-2.amazonaws.com/dummy-api

test:
	@curl dummy-api-lb-950185108.eu-west-2.elb.amazonaws.com

test-greet:
	@curl dummy-api-lb-950185108.eu-west-2.elb.amazonaws.com/greet/Ben

