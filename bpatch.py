#!/usr/bin/env python3
"""
Backward-compatible shim — the real implementation lives in the bpatch/ package.
Run directly:  python bpatch.py <args>
Or via entry-point:  bpatch <args>   (after pip install)
"""
from bpatch.cli import main

if __name__ == "__main__":
    main()
