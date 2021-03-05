from os import environ
import os
from dotenv import load_dotenv
load_dotenv()

def get_env_file(variable_name: str) -> str:
    """Returns a environment variable as path"""
    try:
        path = os.path.abspath(os.environ[variable_name])
        if not path:
            raise RuntimeError(f"Variable is null, Check {variable_name}.")
        with open(path, "r") as f:
            contents = f.read()
        if not contents:
            raise RuntimeError(f"Contents of file empty. Check {variable_name}.")
        return contents
    except KeyError:
        raise RuntimeError(f"Variable is not set, Check {variable_name}.")

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


# Jwt Keys
ID_TOKEN_PRIVATE_KEY_ABSOLUTE_PATH = get_env_file('ID_TOKEN_PRIVATE_KEY_ABSOLUTE_PATH')
JWT_PRIVATE_KEY_ABSOLUTE_PATH = get_env_file("JWT_PRIVATE_KEY_ABSOLUTE_PATH")
