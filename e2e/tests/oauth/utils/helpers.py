def remove_keys(data: dict, keys_to_remove: dict) -> dict:
    """Returns all the params with specified keys removed"""
    for key in keys_to_remove:
        data.pop(key)
    return data


def replace_keys(data: dict, keys_to_replace: dict) -> dict:
    return {**data, **keys_to_replace}
