import os


# Configure Test Environment
def get_env(variable_name: str, default: str = "") -> str:
    """Returns a environment variable"""
    try:
        return os.environ[variable_name]
    except KeyError:
        return default


ENV = {
    'oauth': {
        'apigee_client_id': get_env('APIGEE_CLIENT_ID'),

        'base_url': get_env('BASE_URL'),
        'client_id': get_env('CLIENT_ID'),
        'client_secret': get_env('CLIENT_SECRET'),
        'redirect_uri': get_env('REDIRECT_URI'),

        'authentication_provider': get_env('AUTHENTICATION_PROVIDER', default='Simulated OAuth'),
        'authenticate_url': get_env('AUTHENTICATE_URL'),
        'authenticate_username': get_env('AUTHENTICATE_USERNAME'),
        'authenticate_password': get_env('AUTHENTICATE_PASSWORD'),

        # Invalid ASID Application details
        'invalid_asic_client_id': get_env('INVALID_ASID_CLIENT_ID'),
        'invalid_asid_client_secret': get_env('INVALID_ASID_CLIENT_SECRET'),
        'invalid_asid_redirect_uri': get_env('INVALID_ASID_REDIRECT_URI'),
    },
    'apigee': {
        'base_url': get_env('APIGEE_API_URL'),
        'api_authentication': get_env('APIGEE_API_AUTHENTICATION'),
    },
    'hello_world': {
        'api_url': get_env('API_URL'),
    },
    'pds': {
        'base_url': get_env('PDS_BASE_URL'),
        'application_name': get_env('PDS_APPLICATION'),
    }
}
