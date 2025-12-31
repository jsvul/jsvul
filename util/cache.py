import json
import logging
import re
from pathlib import Path

from util.common import FilteredData, json_defaults, order_dict, MergedCommitData, CVEData, GitHubFile, Date
from util.filter import MinifiedStats
from util.label import ExtractedFunction

logger = logging.getLogger(__name__)

EMPTY_VALUE = {"empty": True}


def cache(filename, filtered=False):
    def decorator(func):
        def wrapper(*args, **kwargs):
            result = read_cache(filename, convert_filtered_data if filtered else None)
            if not result:
                result = func(*args, **kwargs)
                write_cache(filename, result)

            return result

        return wrapper

    return decorator


def convert_filtered_data(f):
    return json.load(f, object_hook=FilteredData.from_dict)


def convert_merged_data(f):
    return json.load(f, object_hook=lambda o: MergedCommitData.from_dict(
        CVEData.from_dict(
            GitHubFile.from_dict(
                Date.from_dict(o)
            )
        )
    ))


def convert_extracted_data(f):
    return json.load(f, object_hook=ExtractedFunction.from_dict)


def convert_minified_data(f):
    return json.load(f, object_hook=MinifiedStats.from_dict)


def read_cache(file_name, convert_func=None) -> dict:
    """
    Reads the cache from a JSON file.
    """
    try:
        with open(file_name, "r", encoding="utf-8") as f:
            if convert_func:
                return convert_func(f)

            else:
                return json.load(f)

    except FileNotFoundError:
        pass

    except Exception as e:
        logger.debug(f"Error reading cache file: {e}")

    return {}


def write_cache(file_name: Path, cache: dict):
    """
    Writes the cache to a JSON file.
    """
    try:
        file_name.parent.mkdir(parents=True, exist_ok=True)
        with open(file_name, "w", encoding="utf-8") as f:
            json.dump(order_dict(cache), f, indent=2, default=json_defaults)

    except Exception as e:
        logger.debug(f"Error writing cache to file: {e}")


def get_cache_file_name(cache_root, url):
    url_simplified = re.sub(r"[/:?#]+", "_", url)
    return cache_root / f"{url_simplified}.json"
