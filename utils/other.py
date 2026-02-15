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

def scan_extra_ssl_pairs(extra_dirs):
    """Рекурсивно ищет пары cert/key в EXTRA_CERT_DIRS для не-nginx сервисов.

    Поддерживаемые варианты в одной папке:
      - fullchain.pem + privkey.pem
      - cert.pem + privkey.pem
      - *.crt + *.key (одинаковый basename)

    Возвращает список (cert_path, key_path) с абсолютными путями.
    """
    pairs = []  # list[(cert_path, key_path)]
    seen = set()

    for base in extra_dirs:
        if not base:
            continue
        base = os.path.abspath(base)
        if not os.path.isdir(base):
            logging.warning("EXTRA_CERT_DIRS: папка не найдена/не папка: %s", base)
            continue

        for dirpath, _, filenames in os.walk(base):
            files = set(filenames)

            if "privkey.pem" in files:
                key_path = os.path.join(dirpath, "privkey.pem")
                if "fullchain.pem" in files:
                    cert_path = os.path.join(dirpath, "fullchain.pem")
                    pair = (os.path.abspath(cert_path), os.path.abspath(key_path))
                    if pair not in seen:
                        pairs.append(pair); seen.add(pair)
                if "cert.pem" in files:
                    cert_path = os.path.join(dirpath, "cert.pem")
                    pair = (os.path.abspath(cert_path), os.path.abspath(key_path))
                    if pair not in seen:
                        pairs.append(pair); seen.add(pair)

            for f in files:
                if not f.endswith(".crt"):
                    continue
                base_name = os.path.splitext(f)[0]
                key_name = base_name + ".key"
                if key_name in files:
                    cert_path = os.path.join(dirpath, f)
                    key_path = os.path.join(dirpath, key_name)
                    pair = (os.path.abspath(cert_path), os.path.abspath(key_path))
                    if pair not in seen:
                        pairs.append(pair); seen.add(pair)

    return pairs