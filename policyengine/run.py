#!/usr/bin/env python3
"""Entry point for the PolicyEngine web UI."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import uvicorn

if __name__ == "__main__":
    print("=" * 60)
    print("  PolicyEngine Web UI")
    print("  http://localhost:8000")
    print("=" * 60)
    uvicorn.run(
        "web.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        reload_dirs=["src", "web"],
    )
