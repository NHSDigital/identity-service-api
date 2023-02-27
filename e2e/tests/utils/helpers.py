import jwt
import requests
import json

from lxml import html
from urllib.parse import urlparse, parse_qs

from e2e.tests.utils.config import (
    ID_TOKEN_NHS_LOGIN_PRIVATE_KEY_ABSOLUTE_PATH,
    JWT_PRIVATE_KEY_ABSOLUTE_PATH,
)


def remove_keys(data: dict, keys_to_remove: dict) -> dict:
    """Returns all the params with specified keys removed"""
    for key in keys_to_remove:
        data.pop(key)
    return data


def replace_keys(data: dict, keys_to_replace: dict) -> dict:
    return {**data, **keys_to_replace}


def subscribe_app_to_products(
    apigee_edge_session, apigee_app_base_url, credential, app_name, products
):
    key = credential["consumerKey"]
    attributes = credential["attributes"]
    url = f"{apigee_app_base_url}/{app_name}/keys/{key}"

    for product in credential["apiProducts"]:
        if product["apiproduct"] not in products:
            products.append(product["apiproduct"])

    product_data = {"apiProducts": products, "attributes": attributes}

    return apigee_edge_session.post(url, json=product_data)


def unsubscribe_product(
    apigee_edge_session, apigee_app_base_url, key, app_name, product_name
):
    url = f"{apigee_app_base_url}/{app_name}/keys/{key}/apiproducts/{product_name}"

    return apigee_edge_session.delete(url)


def change_jwks_url(
    apigee_edge_session,
    apigee_app_base_url,
    app,
    new_jwks_resource_url=None,
    should_remove=False,
):
    app_name = app["name"]
    url = f"{apigee_app_base_url}/{app_name}/attributes/jwks-resource-url"
    if should_remove:
        return apigee_edge_session.delete(url)
    else:
        return apigee_edge_session.post(
            url,
            json={"name": "jwks-resource-url", "value": new_jwks_resource_url},
        )


def create_client_assertion(
    claims, private_key, additional_headers={"kid": "test-1"}, algorithm="RS512"
):
    return jwt.encode(
        claims, private_key, algorithm=algorithm, headers=additional_headers
    )


def create_subject_token(claims, kid="4A72Ed2asGJ0mdjHNTgo8HQJac7kIAKBTsb_sM1ikn8"):
    with open(JWT_PRIVATE_KEY_ABSOLUTE_PATH, "r") as f:
        id_token_private_key = f.read()

    headers = ({}, {"kid": kid})[kid is not None]
    return jwt.encode(claims, id_token_private_key, algorithm="RS512", headers=headers)


def create_nhs_login_subject_token(claims, headers):
    with open(ID_TOKEN_NHS_LOGIN_PRIVATE_KEY_ABSOLUTE_PATH, "r") as f:
        id_token_nhs_login = f.read()

    return jwt.encode(
        payload=claims, key=id_token_nhs_login, algorithm="RS512", headers=headers
    )


def get_auth_info(url, authorize_params, username, headers=None, callback_headers=None):
    # Log in to Keycloak and get code
    session = requests.Session()

    resp = session.get(url=url, params=authorize_params, headers=headers, verify=False)

    if callback_headers is not None:
        session.headers.update(callback_headers)

    tree = html.fromstring(resp.content.decode())

    form = tree.get_element_by_id("kc-form-login")
    url = form.action

    resp2 = session.post(url, data={"username": username})

    return urlparse(resp2.history[-1].headers["Location"]).query


def get_auth_item(auth_info, item):
    auth_item = parse_qs(auth_info)[item]
    if isinstance(auth_item, list):
        auth_item = auth_item[0]

    return auth_item

def get_variable_from_trace(debug, session_name, variable):
    trace_ids = debug.get_transaction_data(session_name=session_name)
    trace_data = debug.get_transaction_data_by_id(
        session_name=session_name, transaction_id=trace_ids[0]
    )

    payload = debug.get_apigee_variable_from_trace(
        name=variable, data=trace_data
    )

    return json.loads(payload)
