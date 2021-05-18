from os import environ
from urllib.parse import urlparse
from dotenv import load_dotenv
load_dotenv()

# Oauth details
OAUTH_BASE_URI = environ.get("OAUTH_BASE_URI")
OAUTH_PROXY = environ.get("OAUTH_PROXY")
OAUTH_URL = f"{OAUTH_BASE_URI}/{OAUTH_PROXY}"
ENVIRONMENT = urlparse(OAUTH_BASE_URI).hostname.split('.')[0]
SERVICE_NAME = environ.get(
    "SERVICE_NAME",
    (f'identity-service-{ENVIRONMENT}', OAUTH_PROXY.replace('oauth2', 'identity-service'))["pr" in OAUTH_PROXY]
)

# Test API (Hello World)
HELLO_WORLD_API_URL = f"{OAUTH_BASE_URI}/hello-world/hello/user"


# Jwt Keys
ID_TOKEN_NHS_LOGIN_PRIVATE_KEY_ABSOLUTE_PATH = environ.get('ID_TOKEN_NHS_LOGIN_PRIVATE_KEY_ABSOLUTE_PATH')
ID_TOKEN_PRIVATE_KEY_ABSOLUTE_PATH = environ.get('ID_TOKEN_PRIVATE_KEY_ABSOLUTE_PATH')
JWT_PRIVATE_KEY_ABSOLUTE_PATH = environ.get("JWT_PRIVATE_KEY_ABSOLUTE_PATH")
