from pathlib import Path
import json, os

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG = ROOT / "config" / "secnet.yaml"
REGISTRY = ROOT / "docs" / "cspm-policy-registry.json"
OUTPUT = ROOT / "tests" / "outputs"

def load_registry(path=REGISTRY):
    return json.loads(Path(path).read_text(encoding="utf-8"))

def ensure_output():
    OUTPUT.mkdir(parents=True, exist_ok=True)
    return OUTPUT
