# Identity Service Tests

This is a collection of end-to-end test suites to verify the oauth api is working as intended.

* `scripts/` A set of methods, classes and scripts to help facilitate the test cases
* `scripts/config.py` This contains environment configuration for running the tests.
* `performance/` A set of requests to stimulate multiple users on the service
* `tests/` The tests are defined here.

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
 * `APIGEE_ENVIRONMENT`
 * `PROXY_NAME` Will be the fully-qualified-service-name
 * `API_NAME` In this case will be "identity-service"
 * `JWT_PRIVATE_KEY_ABSOLUTE_PATH`
 * `ID_TOKEN_NHS_LOGIN_PRIVATE_KEY_ABSOLUTE_PATH`
 * ``APIGEE_ACCESS_TOKEN=`get_token -u YOUR_APIGEE_USERNAME` ``  uses the Apigee [get token](https://docs.apigee.com/api-platform/system-administration/auth-tools#install) utility.

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
The fixtures are defined in the conftest.py file. To learn more about fixtures please visit
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
