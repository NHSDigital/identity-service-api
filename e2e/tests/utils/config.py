from os import environ


# Identity Service details
PROXY_NAME = environ["PROXY_NAME"]
ENVIRONMENT = environ["APIGEE_ENVIRONMENT"]
API_NAME = "identity-service"

# Test API (Canary API)
CANARY_PRODUCT_NAME = f"canary-api-{ENVIRONMENT}"
CANARY_API_URL = f"https://{ENVIRONMENT}.api.service.nhs.uk/canary-api"


# Jwt Keys
ID_TOKEN_NHS_LOGIN_PRIVATE_KEY_ABSOLUTE_PATH = environ[
    "ID_TOKEN_NHS_LOGIN_PRIVATE_KEY_ABSOLUTE_PATH"
]
JWT_PRIVATE_KEY_ABSOLUTE_PATH = environ["JWT_PRIVATE_KEY_ABSOLUTE_PATH"]
