from dataclasses import dataclass
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parent.parent
"The absolute path to the swanky cargo workspace root"

NIX_CACHE_KEY = "NIX_CACHE_KEY"
"ClickContext.obj[NIX_CACHE_KEY] contains a hash of the Nix environment of cli.nix"
