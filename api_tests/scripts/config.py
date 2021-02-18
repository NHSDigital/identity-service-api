from os import environ


def _get_service_name():
    if "pr" in OAUTH_PROXY:
        return OAUTH_PROXY.replace('oauth2', 'identity-service')
    return 'identity-service-internal-dev'


# Oauth details
OAUTH_BASE_URI = environ["OAUTH_BASE_URI"]
OAUTH_PROXY = environ["OAUTH_PROXY"]
SERVICE_NAME = environ.get(
    "SERVICE_NAME",
    ('identity-service-internal-dev', OAUTH_PROXY.replace('oauth2', 'identity-service'))["pr" in OAUTH_PROXY]
)

TOKEN_URL = f"{OAUTH_BASE_URI}/{OAUTH_PROXY}/token"

# Test API (Hello World)
HELLO_WORLD_API_URL = environ.get("HELLO_WORLD_API_URL", None)
