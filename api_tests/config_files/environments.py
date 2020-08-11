import os


# Configure Test Environment
def get_env(variable_name: str) -> str:
    """Returns a environment variable"""
    try:
        return os.environ[variable_name]
    except KeyError:
        return ""


ENV = {
    'oauth': {
        'base_url': get_env('BASE_URL'),
        'client_id': get_env('CLIENT_ID'),
        'client_secret': get_env('CLIENT_SECRET'),
        'redirect_uri': get_env('REDIRECT_URI'),

        'authentication_provider': get_env('AUTHENTICATION_PROVIDER'),
        'authenticate_url': get_env('AUTHENTICATE_URL'),
        'authenticate_username': get_env('AUTHENTICATE_USERNAME'),
        'authenticate_password': get_env('AUTHENTICATE_PASSWORD'),

        'apigee_client_id': get_env('APIGEE_CLIENT_ID'),
        'api_url': get_env('API_URL'),
    },
}
