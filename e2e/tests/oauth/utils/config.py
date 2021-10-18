from e2e.tests.oauth.utils.environment import EnvVarWrapper


ENV = EnvVarWrapper(
    **{
        "environment": "APIGEE_ENVIRONMENT",
        "pds_base_path": "PDS_BASE_PATH",
        'client_id': 'CLIENT_ID',
        'client_secret': 'CLIENT_SECRET',
        'redirect_uri': 'REDIRECT_URI',
        'authenticate_url': 'AUTHENTICATE_URL',
        'test_patient_id': 'TEST_PATIENT_ID',
    }
)

# Api Details
ENVIRONMENT = ENV["environment"]
BASE_URL = f"https://{ENVIRONMENT}.api.service.nhs.uk"  # Apigee proxy url

IDENTITY_SERVICE = "oauth2-no-smartcard" if ENVIRONMENT == "int" else "oauth2"

AUTHORIZE_URL = f"{BASE_URL}/{IDENTITY_SERVICE}/authorize"
TOKEN_URL = f"{BASE_URL}/{IDENTITY_SERVICE}/token"
SIM_AUTH_URL = f"{BASE_URL}/{IDENTITY_SERVICE}/simulated_auth"
AUTHENTICATE_URL = ENV["authenticate_url"]
CALLBACK_URL = f"{BASE_URL}/{IDENTITY_SERVICE}/callback"

# App details
CLIENT_ID = ENV["client_id"]
CLIENT_SECRET = ENV["client_secret"]
REDIRECT_URI = ENV["redirect_uri"]

# Endpoints
ENDPOINTS = {
    "authorize": AUTHORIZE_URL,
    "token": TOKEN_URL,
    "authenticate": AUTHENTICATE_URL,
    "callback": CALLBACK_URL,
    "sim_auth": SIM_AUTH_URL,
}
