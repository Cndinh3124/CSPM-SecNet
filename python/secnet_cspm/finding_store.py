from pathlib import Path
import json
from .config import ensure_output

def save_json(name, data):
    path = ensure_output() / name
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return path

def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))
