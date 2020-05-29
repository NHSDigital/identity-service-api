FROM python:3.8-slim

# Maintainers
MAINTAINER API Management Team

# Update if required
RUN mkdir -p /var/api_tests/
RUN apt update -y && apt upgrade -y

# Set up test environment
COPY "." "/var/api_tests"
RUN pip install --upgrade pip
RUN pip install -r /var/api_tests/requirements.txt

WORKDIR "/var/api_tests/"

ENV PYTHONPATH=/var/api-tests/:

CMD tail -f /dev/null
