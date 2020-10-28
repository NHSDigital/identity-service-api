from .environments import ENV
from pathlib import Path
from os import getcwd

# api_test directory
HOME = Path(getcwd()).parent.parent

# Api details
APIGEE_CLIENT_ID = ENV['oauth']['apigee_client_id']
BASE_URL = ENV['oauth']['base_url']
AUTHORIZE_URL = f"{BASE_URL}/authorize"
TOKEN_URL = f"{BASE_URL}/token"

# Apigee API details
APIGEE_API_URL = ENV['apigee']['base_url']
APIGEE_AUTHENTICATION = ENV['apigee']['api_authentication']
APIGEE_ENVIRONMENT = "internal-dev"

# PDS
PDS_BASE_URL = ENV['pds']['base_url']
PDS_PROXY = ENV['pds']['proxy_name']
PDS_API = f"{PDS_BASE_URL}/{PDS_PROXY}/Patient"

# App details
CLIENT_ID = ENV['oauth']['client_id']
CLIENT_SECRET = ENV['oauth']['client_secret']
REDIRECT_URI = ENV['oauth']['redirect_uri']

# Authentication provider (Simulated OAuth)
AUTHENTICATE_URL = ENV['oauth']['authenticate_url']

# Test API (Hwllo World)
HELLO_WORLD_API_URL = ENV['hello_world']['api_url']

# JWT config
JWT_PRIVATE_KEY = ENV['jwt']['private_key']
JWT_APP_KEY = ENV['jwt']['app_key']
JWT_APP_KEY_WITH_INVALID_JWKS_URL = "kstRcl8syAA0CRqFeRBaMG0GiXgLBR2i"

# Endpoints
ENDPOINTS = {
    'authorize': AUTHORIZE_URL,
    'token': TOKEN_URL,
    'authenticate': AUTHENTICATE_URL,
    'hello_world': HELLO_WORLD_API_URL,
    'pds': PDS_API,
}

# Flag to indicate if tests are running locally or remotely i.e. in the pipeline
# Toggles token type set:
#        True: 'Bearer'
#        False: 'Basic'
IS_REMOTE = True
