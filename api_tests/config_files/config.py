from .environments import ENV


# Api details
APIGEE_CLIENT_ID = ENV['oauth']['apigee_client_id']
IDENTITY_PROXY = ENV['oauth']['identity_proxy']
BASE_URL = ENV['oauth']['base_url']
AUTHORIZE_URL = f"{BASE_URL}/{IDENTITY_PROXY}/authorize"
TOKEN_URL = f"{BASE_URL}/{IDENTITY_PROXY}/token"
SIM_AUTH_URL = f"{BASE_URL}/{IDENTITY_PROXY}/simulated_auth"

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

# Test API
API_URL = ENV['hello_world']['api_url']

# Endpoints
ENDPOINTS = {
    'authorize': AUTHORIZE_URL,
    'token': TOKEN_URL,
    'authenticate': AUTHENTICATE_URL,
    'api': API_URL,
    'pds': PDS_API,
}

# Flag to indicate if tests are running locally or remotely i.e. in the pipeline
# Toggles token type set:
#        True: 'Bearer'
#        False: 'Basic'
IS_REMOTE = True
