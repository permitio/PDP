def get_case_insensitive(dictionary, key) -> str | None:
    if isinstance(key, str):
        return next((dictionary[k] for k in dictionary if k.lower() == key.lower()), None)
    return dictionary.get(key, None)
