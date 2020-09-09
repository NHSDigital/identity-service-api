from .environments import ENV


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
PDS_APPLICATION = ENV['pds']['application_name']
PDS_API = f"{PDS_BASE_URL}/{PDS_APPLICATION}/Patient"

# App details
CLIENT_ID = ENV['oauth']['client_id']
CLIENT_SECRET = ENV['oauth']['client_secret']
REDIRECT_URI = ENV['oauth']['redirect_uri']

# Sign in details
AUTHENTICATION_PROVIDER = ENV['oauth']['authentication_provider']
AUTHENTICATE_URL = ENV['oauth']['authenticate_url']
USERNAME = ENV['oauth']['authenticate_username']
PASSWORD = ENV['oauth']['authenticate_password']

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
