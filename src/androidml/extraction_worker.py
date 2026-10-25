"""Internal subprocess entry point. No APK installation/execution occurs."""
from __future__ import annotations
import json
import sys
from pathlib import Path
from .extract import _extract_in_process

def main() -> int:
    if len(sys.argv) != 3:
        return 2
    result = _extract_in_process(Path(sys.argv[1]))
    Path(sys.argv[2]).write_text(json.dumps(result, ensure_ascii=False, allow_nan=False) + "\n", encoding="utf-8")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
