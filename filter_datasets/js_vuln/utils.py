import json


def load_json_file(filename):
    """
    Load a JSON file from the collected info directory.
    """
    with open(filename, "r", encoding="utf-8") as f:
        return json.load(f)
