"""Pytest configuration - shared orchestration path setup."""
import sys
from pathlib import Path

# Add shared ops to path for pytest
shared_ops = Path(__file__).parent.parent / "shared-orchestration" / "scripts" / "ops"
if shared_ops.exists() and str(shared_ops) not in sys.path:
    sys.path.insert(0, str(shared_ops))

# Also add local scripts/ops
local_ops = Path(__file__).parent / "scripts" / "ops"
if local_ops.exists() and str(local_ops) not in sys.path:
    sys.path.insert(0, str(local_ops))
