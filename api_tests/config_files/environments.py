import os


# Configure Test Environment
def get_env(string):
    """Returns a environment variable"""
    try:
        return os.environ[string]
    except:
        return ""


ENV = {
    'oauth': {
        'base_url': get_env('BASE_URL'),
        'client_id': get_env('CLIENT_ID'),
        'client_secret': get_env('CLIENT_SECRET'),
        'redirect_uri': get_env('REDIRECT_URI'),

        'authenticate_url': get_env('AUTHENTICATE_URL'),
        'authenticate_username': get_env('AUTHENTICATE_USERNAME'),
        'authenticate_password': get_env('AUTHENTICATE_PASSWORD')
    },
}
