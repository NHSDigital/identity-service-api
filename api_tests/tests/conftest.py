import pytest
from api_tests.scripts.check_oauth_endpoints import CheckOauthEndpoints


@pytest.fixture(scope='function')
def setup(request):
    """This function is called before each and every test is executed"""
    name = (request.node.name, request.node.originalname)[request.node.originalname is not None]
    setattr(request.cls, "name", name)

    test = CheckOauthEndpoints()
    setattr(request.cls, "test", test)
