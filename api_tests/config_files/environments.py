import os


# Configure Test Environment
def get_env(variable_name: str) -> str:
    """Returns a environment variable"""
    try:
        var = os.environ[variable_name]
        if not var:
            raise RuntimeError(f"Variable is null, Check {variable_name}.")
        return var
    except KeyError:
        raise RuntimeError(f"Variable is not set, Check {variable_name}.")


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


ENV = {
    'oauth': {
        'apigee_client_id': get_env('APIGEE_CLIENT_ID'),

        'identity_proxy': get_env('IDENTITY_PROXY'),
        'base_url': get_env('BASE_URL'),
        'client_id': get_env('CLIENT_ID'),
        'client_secret': get_env('CLIENT_SECRET'),
        'redirect_uri': get_env('REDIRECT_URI'),
        'authenticate_url': get_env('AUTHENTICATE_URL'),

        # Valid but unsubscribed app details
        'valid_unsubscribed_client_id': get_env('VALID_UNSUBSCRIBED_CLIENT_ID'),
        'valid_unsubscribed_client_secret': get_env('VALID_UNSUBSCRIBED_CLIENT_SECRET'),
        'valid_unsubscribed_redirect_uri': get_env('VALID_UNSUBSCRIBED_REDIRECT_URI'),

        # Valid but unapproved app details
        'valid_unapproved_client_id': get_env('VALID_UNAPPROVED_CLIENT_ID'),
        'valid_unapproved_client_secret': get_env('VALID_UNAPPROVED_CLIENT_SECRET'),
        'valid_unapproved_redirect_uri': get_env('VALID_UNAPPROVED_REDIRECT_URI'),

        # Invalid ASID Application details
        'invalid_asic_client_id': get_env('INVALID_ASID_CLIENT_ID'),
        'invalid_asid_client_secret': get_env('INVALID_ASID_CLIENT_SECRET'),

        # Valid ASID Application details
        'valid_asic_client_id': get_env('VALID_ASID_CLIENT_ID'),
        'valid_asid_client_secret': get_env('VALID_ASID_CLIENT_SECRET'),

        # Missing ASID Application details
        'missing_asic_client_id': get_env('MISSING_ASID_CLIENT_ID'),
        'missing_asid_client_secret': get_env('MISSING_ASID_CLIENT_SECRET'),

    },
    'apigee': {
        'base_url': get_env('APIGEE_API_URL'),
        'api_authentication': get_env('APIGEE_API_AUTHENTICATION'),
    },
    'hello_world': {
        'api_url': get_env('HELLO_WORLD_API_URL'),
    },
    'pds': {
        'base_url': get_env('PDS_BASE_URL'),
        'proxy_name': get_env('PDS_PROXY'),
    },
    "jwt": {
        'app_key': get_env('JWT_APP_KEY'),
        'private_key': get_env_file('PRIVATE_KEY_DIR'),
    },
}
