import logging
import os
import tempfile
from typing import List


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)

def atomic_update_link_or_file(link_path: str, target_path: str, timestamp: str, dry_run: bool) -> None:
    """
    Если link_path — симлинк: заменяем атомарно.
    Если обычный файл: бэкапим и заменяем на симлинк.
    """
    ensure_dir(os.path.dirname(link_path))

    if dry_run:
        logging.info("[dry-run] Обновил бы %s -> %s", link_path, target_path)
        return

    if os.path.exists(link_path) and not os.path.islink(link_path) and os.path.isfile(link_path):
        backup = f"{link_path}.bak-{timestamp}"
        logging.info("Бэкап файла %s -> %s", link_path, backup)
        os.replace(link_path, backup)

    tmp = f"{link_path}.tmp-{os.getpid()}"
    try:
        if os.path.lexists(tmp):
            os.unlink(tmp)
        os.symlink(target_path, tmp)
        os.replace(tmp, link_path)
    finally:
        try:
            if os.path.lexists(tmp):
                os.unlink(tmp)
        except Exception:
            pass

def write_file(path: str, data: str, mode: int) -> None:
    # атомарная запись через temp + replace
    d = os.path.dirname(path)
    ensure_dir(d)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(data)
            if not data.endswith("\n"):
                f.write("\n")
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        try:
            if os.path.exists(tmp):
                os.unlink(tmp)
        except Exception:
            pass


def path_allowed(path: str, prefixes: List[str]) -> bool:
    ap = os.path.abspath(path)
    for p in prefixes:
        if ap.startswith(os.path.abspath(p).rstrip("/") + "/") or ap == os.path.abspath(p):
            return True
    return False