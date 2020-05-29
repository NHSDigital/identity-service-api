from .environments import ENV


# Api details
APIGEE_CLIENT_ID = ENV['oauth']['apigee_client_id']
BASE_URL = ENV['oauth']['base_url']
AUTHORIZE_URL = f"{BASE_URL}/authorize"
TOKEN_URL = f"{BASE_URL}/token"

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
API_URL = ENV['oauth']['api_url']
