# Identity Service Tests

This is a collection of end-to-end test suites to verify the oauth api is working as intended.

* `tests/` The tests are defined here.
* `tests/utils/` configuration and helper functions used by the tests are defined here.
* `tests/utils/config.py` This contains environment configuration for running the tests.
* `tests/conftest.py` Fixtures used by the tests are defined here. Some fixtures are predefined by the pytest_nhsd_apim package.
* `performance/` A set of requests to stimulate multiple users on the service

We are using pytest as our test runner, you can find out more about pytest by visiting
the [pytest docs](https://docs.pytest.org/en/latest/).

## Requirements
* python 3.8
* [make](http://gnuwin32.sourceforge.net/packages/make.htm) this comes pre-installed on Linux or Mac.
* Apigee [get token](https://docs.apigee.com/api-platform/system-administration/auth-tools#install) utility.
* run `make install` from root of project

### Environment Variables
Before you can start creating and running tests you need to configure all the required environment variables.

Variables required for running non performance tests are listed below:
 * `APIGEE_ENVIRONMENT` - The Apigee environment you're running the tests against
 * `PROXY_NAME` -  This will be the fully-qualified-service-name of the identity service proxy you're using (sometimes a pull request)
 * `API_NAME` -  In this case will be "identity-service"
 * `JWT_PRIVATE_KEY_ABSOLUTE_PATH` - Stored in AWS Secrets Manager at ptl/app-credentials/jwt_testing/non-prod/JWT_TESTING_PRIVATE_KEY
 * `ID_TOKEN_NHS_LOGIN_PRIVATE_KEY_ABSOLUTE_PATH` -  Stored in AWS Secrets Manager at ptl/app-credentials/jwt_testing/non-prod/ID_TOKEN_NHS_LOGIN_PRIVATE_KEY
 * ``APIGEE_ACCESS_TOKEN=`get_token -u YOUR_APIGEE_USERNAME` `` -   uses the Apigee [get token](https://docs.apigee.com/api-platform/system-administration/auth-tools#install) utility.

## pytest_nhsd_apim test package
The end to end tests for identity service use the API Management Platforms's testing package `pytest_nhsd_apim`. The package provides fixtures and markers that allow easy integration with Apigee and Platform resources.

For details on how to use these features see:
* [API Producer Zone documentation](https://nhsd-confluence.digital.nhs.uk/display/APM/APIM+Test+Utils+2.0+plugin) - for how to use it
* [pytest_nhsd_apim repo](https://github.com/NHSDigital/pytest-nhsd-apim) - for how it works
* [pytest_nhsd_apim test examples](https://github.com/NHSDigital/pytest-nhsd-apim/blob/main/tests/test_examples.py)  - to see the features in action

## Running tests
Test can be either executed using a virtual env and from a terminal/command window or from within an IDE. These are explained below.

### Execute locally
In order to run the tests, make sure you have a command window or terminal open and activate your virtualenv.

Follow the pytest example commands below to begin running your tests:

```shell
# Runs all tests
make e2e

# Runs specific test file
poetry run pytest <path_to_file>

# Runs tests in a class in a test file
poetry run pytest <path_to_file>::TestClassSuite

# Runs a single test method
poetry run pytest <path_to_file>::TestClassSuite::test_method
```
### Other useful Pytest commands
 * `quiet mode` --pytest -q
 * `verbose mode` --pytest -v
 * `keywords` -- pytest -k "KEYWORD" -k "KEYWORD_1 or KEYWORD_2" -k "KEYWORD_1 and KEYWORD_2"
 * `marks` -- pytest -m MARK
 * `stop after first failure` -- pytest -x
 * `display print statements` -- pytest -s

### Marks
Tests can be marked with specific 'marks'. Think of marks as tagging a test with some metadata.
These marks are defined in the pytest.ini file and must be strictly followed
(meaning you can only use the marks that have been predefined).
To create a new mark you simply insert a new line in the pytest.ini file
following the convention: mark_name: mark_description.

### Adding Marks to Tests
You can add one or more marks to a test. To add a mark simply define a decorator to the test.

Example:

```python
@pytest.mark.name_of_mark
@pytest.mark.name_of_another_mark
def test_example():
    assert some_test_method()
```

Example running all the tests that have been marked with the "name_of_mark" mark:

``` shell
pytest -m name_of_mark -v tests/
```

### Fixtures
pytest has which we can utilise to help us setup and teardown each test. We use a decorator to assign a fixture to a
function, method or class. A fixture can also be scoped to run either at session time or per function/method.
The fixtures are defined in the e2e/conftest.py file. To learn more about fixtures please visit
the [pytest docs](https://docs.pytest.org/en/latest/fixture.html)

```
## Contributing
Contributions to this project are welcome from anyone, providing that they conform to
the [guidelines for contribution](https://github.com/NHSDigital/template-api/blob/master/CONTRIBUTING.md) and
the [community code of conduct](https://github.com/NHSDigital/template-api/blob/master/CODE_OF_CONDUCT.md).

### Licensing
This code is licensed under the MIT license. Any new work added to this repository must conform to the
conditions of this licenses. In particular this means that this project may not depend on GPL-licensed or
AGPL-licensed libraries, as these would violate the terms of those libraries' licenses.

The contents of this repository are protected by Crown Copyright (C)
