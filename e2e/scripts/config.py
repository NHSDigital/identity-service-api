from os import environ
from urllib.parse import urlparse


# Oauth details
OAUTH_BASE_URI = environ["OAUTH_BASE_URI"]
OAUTH_PROXY = environ["OAUTH_PROXY"]
OAUTH_URL = f"{OAUTH_BASE_URI}/{OAUTH_PROXY}"
API_NAME = "identity-service"
PROXY_NAME = environ["FULLY_QUALIFIED_SERVICE_NAME"]
environ["PROXY_NAME"] = PROXY_NAME
MOCK_IDP_BASE_URL = environ.get("MOCK_IDP_BASE_URL", "https://internal-dev.api.service.nhs.uk/mock-nhsid-jwks")
print(OAUTH_BASE_URI)
ENVIRONMENT = urlparse(OAUTH_BASE_URI).hostname.split('.')[0]
SERVICE_NAME = environ.get(
    "SERVICE_NAME",
    (f'identity-service-{ENVIRONMENT}', OAUTH_PROXY.replace('oauth2', 'identity-service'))["pr" in OAUTH_PROXY]
)
API_NAME=SERVICE_NAME

# Test API (Canary API)
CANARY_API_URL = f"{OAUTH_BASE_URI}/canary-api"


# Jwt Keys
ID_TOKEN_NHS_LOGIN_PRIVATE_KEY_ABSOLUTE_PATH = environ["ID_TOKEN_NHS_LOGIN_PRIVATE_KEY_ABSOLUTE_PATH"]
ID_TOKEN_PRIVATE_KEY_ABSOLUTE_PATH = environ["ID_TOKEN_PRIVATE_KEY_ABSOLUTE_PATH"]
JWT_PRIVATE_KEY_ABSOLUTE_PATH = environ["JWT_PRIVATE_KEY_ABSOLUTE_PATH"]

# _status endpoint api-key
STATUS_ENDPOINT_API_KEY = environ["STATUS_ENDPOINT_API_KEY"]
