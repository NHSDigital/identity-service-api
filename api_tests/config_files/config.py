from .environments import ENV


# Api details
APIGEE_CLIENT_ID = ENV['oauth']['apigee_client_id']
IDENTITY_PROXY = ENV['oauth']['identity_proxy']
BASE_URL = ENV['oauth']['base_url']

AUTHORIZE_URL = f"{BASE_URL}/{IDENTITY_PROXY}/authorize"
TOKEN_URL = f"{BASE_URL}/{IDENTITY_PROXY}/token"
SIM_AUTH_URL = f"{BASE_URL}/{IDENTITY_PROXY}/simulated_auth"
CALLBACK_URL = f"{BASE_URL}/{IDENTITY_PROXY}/callback"
USERINFO_URL = f"{BASE_URL}/{IDENTITY_PROXY}/userinfo"

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

# Details of valid app that is not subscribed
VALID_UNSUBSCRIBED_CLIENT_ID = ENV['oauth']['valid_unsubscribed_client_id']
VALID_UNSUBSCRIBED_CLIENT_SECRET = ENV['oauth']['valid_unsubscribed_client_secret']
VALID_UNSUBSCRIBED_REDIRECT_URI = ENV['oauth']['valid_unsubscribed_redirect_uri']

# Details of valid app that is not approved
VALID_UNAPPROVED_CLIENT_ID = ENV['oauth']['valid_unapproved_client_id']
VALID_UNAPPROVED_CLIENT_SECRET = ENV['oauth']['valid_unapproved_client_secret']
VALID_UNAPPROVED_CLIENT_REDIRECT_URI = ENV['oauth']['valid_unapproved_redirect_uri']

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
    'callback': CALLBACK_URL,
    'userinfo': USERINFO_URL,
    'hello_world': HELLO_WORLD_API_URL,
    'pds': PDS_API,
    'sim_auth': SIM_AUTH_URL,
    'ping': f'{BASE_URL}/{IDENTITY_PROXY}/_ping'
}

# Flag to indicate if tests are running locally or remotely i.e. in the pipeline
# Toggles token type set:
#        True: 'Bearer'
#        False: 'Basic'
IS_REMOTE = True
