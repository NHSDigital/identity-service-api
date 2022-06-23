# Api-Tests

This is a collection of end-to-end test suits to verify the oauth api is working as intended.

* `scripts/` A set of methods, classes and scripts to help facilitate the test cases
* `scripts/config.py` This contains all the configuration for running the tests.
* `performance/` A set of requests to stimulate multiple users on the service
* `steps/` Reusable steps for a set of test cases
* `tests/` The tests are defined here (this is also where we execute the tests from)

We are using pytest as our test runner, you can find out more about pytest by visiting
the [pytest docs](https://docs.pytest.org/en/latest/).

## Requirements
* python 3.8
* [make](http://gnuwin32.sourceforge.net/packages/make.htm) this comes pre-installed on Linux or Mac.
* Apigee [get token](https://docs.apigee.com/api-platform/system-administration/auth-tools#install) utility.

### Environment Variables
Before you can start creating and running tests you need to configure all the required environment variables.

Variables required for running non performance tests are listed below:
(these are all described in the scripts/config.py file).

 * `OAUTH_BASE_URI` The base url for the OAuth api
 * `OAUTH_PROXY` Used to build oauth url. If pointing to internal-dev value will be `oauth2`, if pointing to pr, add your pr number as follows `oauth2-pr-{pr number}`
 * `JWT_PRIVATE_KEY_ABSOLUTE_PATH`
 * `ID_TOKEN_PRIVATE_KEY_ABSOLUTE_PATH`
 * `ID_TOKEN_NHS_LOGIN_PRIVATE_KEY_ABSOLUTE_PATH`
 * `SSO_LOGIN_URL=https://login.apigee.com` needed for APIGEE_API_TOKEN
 * ``APIGEE_API_TOKEN=`get_token -u YOUR_APIGEE_USERNAME` `` uses the Apigee [get token](https://docs.apigee.com/api-platform/system-administration/auth-tools#install) utility.
  * `STATUS_ENDPOINT_API_KEY` value is required if running status endpoint test

## Running tests
Test can be either executed using a virtual env and from a terminal/command window or from within an IDE (preferably PyCharm). These are explained below.

### Execute locally
In order to run the tests, make sure you have a command window or terminal open and activate your virtualenv.

Follow the pytest example command below to begin running your tests

Pytest command examples:

```shell
# Runs all tests
pytest -v tests/

# Runs specific test file
pytest -v tests/filename.py

# Runs tests in a class in a test file
pytest tests/filename.py::TestClassSuite

# Runs a single test method
pytest tests/filename.py::TestClassSuite::test_method
```
### Other useful Pytest commands
 * `quiet mode` --pytest -q
 * `verbose mode` --pytest -v
 * `keywords` -- pytest -k "KEYWORD" -k "KEYWORD_1 or KEYWORD_2" -k "KEYWORD_1 and KEYWORD_2"
 * `marks` -- pytest -m MARK
 * `stop after first failure` -- pytest -x
 * `display print statements` -- pytest -s
### Running in Pycharm
When developing scripts, it can be incredibly useful to run from inside Pycharm in order to add
breakpoints, debug and follow the code a lot easier etc.

#### Virtual env instance
To set this up, open the project inside the IDE.

1. In the setting menu, select the Project then Project interpreter sub-menu.

2. There is a dropdown box at the top with a small cog button next to it.

3. Click the cog and then add local. Navigate to the folder where your

4. virtualenv is and select the Python.exe from inside the script folder.

This will make sure Pycharm knows to run the tests with the libraries and Python interpreter from the virtualenv.
You should now be able to right click any function/test and run or debug from inside the IDE and
PyCharm features like autocompletion, code inspections, and checks will be driven by this interpreter.

## Developing New Tests
The test runner pytest will pick up any file which start with "test_*.py". New tests should be created
in these files inside a class that follows the convention 'Test*Suite' and individual tests should be in functions
that start with "test_".

Tests are split into various layers. The top layer is in the tests folder and is any file
ending with '_test'. These call reusable steps from files in the steps folder and perform an
assertion. An assertion merely checks if something is true. Therefore, steps from the test layer
should return True or False. These reusable steps are split into classes which represent an api or a
group of smaller functions of an api.

There is one final layer which are the files located in the scripts folder, there are steps that are
reusable across multiple apis. Here we have a parent Base class that all other api checks would inherit from.

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

### Examples
Class fixture
```python
@pytest.mark.usefixtures("setup")
class TestOauthEndpointSuite:
```
Method fixture
```python
@pytest.mark.usefixtures('get_token')
def test_something(self):
    assert self.test.check_endpoint()
```
Test Case
```python
def test_something(self):
    assert self.test.check_endpoint(), "Message if assertion failed"
```
Test methods
```python
@pytest.mark.usefixtures('get_token')
def test_something(self):
    # This will check the endpoint is returning the correct status, response data and headers
    assert self.test.check_endpoint()

    # This will check all the redirects the response had to take and makes sure they were as expected
    assert self.test.check_response_history()
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
