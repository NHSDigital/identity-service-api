import pytest


@pytest.mark.usefixtures("setup")
class TestOauthTokensSuite:
    """ A test suite to confirm Oauth tokens are behaving as expected"""

