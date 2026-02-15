import subprocess
from typing import List, Tuple


def run_cmd(cmd: List[str], check: bool = False) -> Tuple[int, str]:
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out = (p.stdout or "") + (p.stderr or "")
    if check and p.returncode != 0:
        raise RuntimeError(f"Команда упала ({p.returncode}): {' '.join(cmd)}\n{out[:2000]}")
    return p.returncode, out