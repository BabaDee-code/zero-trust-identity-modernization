from __future__ import annotations

import json
import sys
from pathlib import Path

from .engine import evaluate_request


def main(path: str) -> None:
    requests = json.loads(Path(path).read_text(encoding="utf-8"))
    decisions = [evaluate_request(item).to_dict() for item in requests]
    print(json.dumps(decisions, indent=2))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python -m zt_policy_engine.evaluate data/sample_requests.json")
    main(sys.argv[1])
