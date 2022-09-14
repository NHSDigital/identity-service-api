import jwt


def remove_keys(data: dict, keys_to_remove: dict) -> dict:
    """Returns all the params with specified keys removed"""
    for key in keys_to_remove:
        data.pop(key)
    return data


def replace_keys(data: dict, keys_to_replace: dict) -> dict:
    return {**data, **keys_to_replace}


def subscribe_app_to_products(
    apigee_edge_session,
    apigee_app_base_url,
    credential,
    app_name,
    products
):
    key = credential["consumerKey"]
    attributes = credential["attributes"]
    url = f"{apigee_app_base_url}/{app_name}/keys/{key}"

    for product in credential["apiProducts"]:
        if product["apiproduct"] not in products:
            products.append(product["apiproduct"])

    product_data = {
        "apiProducts": products,
        "attributes": attributes
    }

    return apigee_edge_session.post(url, json=product_data)


def unsubscribe_product(
    apigee_edge_session,
    apigee_app_base_url,
    key,
    app_name,
    product_name
):
    url = f"{apigee_app_base_url}/{app_name}/keys/{key}/apiproducts/{product_name}"

    return apigee_edge_session.delete(url)


def create_client_assertion(claims, private_key, additional_headers={"kid": "test-1"}):
    return jwt.encode(
        claims,
        private_key,
        algorithm="RS512",
        headers=additional_headers
    )
