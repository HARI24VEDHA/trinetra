import os
import json
import hashlib
from datetime import datetime

CACHE_FILE = "cache/analysis_cache.json"


class CacheManager:

    def __init__(self):
        if not os.path.exists("cache"):
            os.makedirs("cache")

        if not os.path.exists(CACHE_FILE):
            with open(CACHE_FILE, "w") as f:
                json.dump([], f)

    def generate_file_hash(self, file_path):
        sha256 = hashlib.sha256()

        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                sha256.update(chunk)

        return sha256.hexdigest()

    def load_cache(self):
        with open(CACHE_FILE, "r") as f:
            return json.load(f)

    def save_cache(self, cache_data):
        with open(CACHE_FILE, "w") as f:
            json.dump(cache_data, f, indent=4)

    def get_cached_result(self, file_hash):
        cache = self.load_cache()

        for entry in cache:
            if entry["file_hash"] == file_hash:
                return entry

        return None

    def store_result(self, file_path, result_data):

        file_hash = self.generate_file_hash(file_path)

        cache = self.load_cache()

        entry = {
            "file_hash": file_hash,
            "filename": os.path.basename(file_path),
            "timestamp": datetime.now().isoformat(),
            "result": result_data
        }

        cache.append(entry)

        self.save_cache(cache)

        return entry