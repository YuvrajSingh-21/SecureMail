import json

def get_safe_attr(obj, attr_name, default="N/A"):
    if not obj:
        return default
    return getattr(obj, attr_name, default) or default

def parse_json_field(field_data):
    if isinstance(field_data, dict) or isinstance(field_data, list):
        return field_data
    if isinstance(field_data, str):
        try:
            return json.loads(field_data)
        except (ValueError, TypeError):
            return {}
    return {}
