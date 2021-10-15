# Simulated IdP

## Overview

Under normal/production usage, the Identity Service API Proxy uses a 'backing IdP' to perform user authentication.

For development purposes, the Identity Service can fulfil this role itself. The interface to Client Application developers remains the same.

The user authentication component is 'simulated' - no actual authentication takes place. The user is presented with a HTML login dialogue where they simply click to log in.

## Configuration

### Enable

To enable this mode, create a key `simulated_idp` with a value of `true` in the `VARIABLES_KVM`.

If this key is missing, or set to any other value, normal authentication will apply.

### Setup

To complete configuation:

 * Set the "identity-server" Target Server to the hostname of the API Proxy:
 * In the `VARIABLES_KVM`
    * Set the `authorize_endpoint` to `https://<environment_hostname>/<proxy_base_path>/simulated_auth`
    * `client_id` can be set to anything
    * `jwks_path` and `access_token_path` are no longer used (can be removed)
