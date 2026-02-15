import logging
import os
import re
import shutil
import subprocess
from typing import Tuple, List, Optional, Dict

from utils.cmd import run_cmd


def parse_nginx_ssl_pairs(nginx_bin: str) -> List[Tuple[str, str]]:
    """
    Возвращает список уникальных пар (ssl_certificate, ssl_certificate_key)
    из server-блоков nginx.

    Если nginx отсутствует или не запускается — возвращает пустой список.
    """

    # --- 1. Проверяем наличие nginx ---
    resolved = None

    if os.path.isfile(nginx_bin):
        resolved = nginx_bin
    else:
        resolved = shutil.which(nginx_bin)

    if not resolved:
        logging.warning("nginx не найден: %s", nginx_bin)
        return []

    # --- 2. Выполняем nginx -T ---
    try:
        proc = subprocess.run(
            [resolved, "-T"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except Exception as e:
        logging.warning("Ошибка запуска nginx: %s", e)
        return []

    text = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode != 0 or not text:
        logging.warning("nginx -T завершился с ошибкой (rc=%s)", proc.returncode)
        return []

    # --- 3. Парсим конфиг ---
    lines = text.splitlines()

    type_stack: List[str] = []
    server_data_stack: List[Optional[Dict[str, List[str]]]] = []
    collected_servers: List[Dict[str, List[str]]] = []

    def push(kind: str):
        type_stack.append(kind)
        if kind == "server":
            server_data_stack.append({"certs": [], "keys": []})
        else:
            server_data_stack.append(None)

    def pop():
        if not type_stack:
            return
        kind = type_stack.pop()
        data = server_data_stack.pop()
        if kind == "server" and data:
            collected_servers.append(data)

    pending_server = False

    for raw in lines:
        # убираем комментарии
        line = re.sub(r"#.*$", "", raw).strip()
        if not line:
            continue

        # если уже внутри server — ищем директивы
        if "server" in type_stack:
            m_cert = re.search(r"\bssl_certificate\s+([^;]+);", line)
            m_key = re.search(r"\bssl_certificate_key\s+([^;]+);", line)

            if m_cert and not re.search(r"\bssl_certificate_key\b", line):
                path = m_cert.group(1).strip().strip('"').strip("'")
                if "$" not in path:
                    for i in range(len(type_stack) - 1, -1, -1):
                        if type_stack[i] == "server":
                            server_data_stack[i]["certs"].append(path)
                            break

            if m_key:
                path = m_key.group(1).strip().strip('"').strip("'")
                if "$" not in path:
                    for i in range(len(type_stack) - 1, -1, -1):
                        if type_stack[i] == "server":
                            server_data_stack[i]["keys"].append(path)
                            break

        # если встретили слово server без {
        if re.search(r"\bserver\b", line) and "{" not in line:
            pending_server = True

        # разбор блоков
        i = 0
        while i < len(line):
            if line[i] == "{":
                if re.search(r"\bserver\s*\{", line[: i + 1]) or pending_server:
                    push("server")
                    pending_server = False
                else:
                    push("other")
                i += 1
                continue

            if line[i] == "}":
                pop()
                i += 1
                continue

            i += 1

        if re.search(r"\bserver\s*\{", line):
            pending_server = False

    # добиваем стек если что-то не закрыто
    while type_stack:
        pop()

    # --- 4. Собираем уникальные пары ---
    pairs: List[Tuple[str, str]] = []
    seen = set()

    for s in collected_servers:
        if not s["certs"] or not s["keys"]:
            continue

        cert = s["certs"][0]
        key = s["keys"][0]

        if (cert, key) not in seen:
            seen.add((cert, key))
            pairs.append((cert, key))

    return pairs

def nginx_reload_or_restart(systemctl_bin: str, nginx_bin: str, dry_run: bool) -> None:
    # Перед reload проверим конфиг
    rc, out = run_cmd([nginx_bin, "-t"])
    if rc != 0:
        logging.error("nginx -t не прошёл, reload/restart не делаю:\n%s", out[:2000])
        return

    if dry_run:
        logging.info("[dry-run] systemctl reload nginx")
        logging.info("[dry-run] (если не ок) systemctl restart nginx")
        return

    rc1, out1 = run_cmd([systemctl_bin, "reload", "nginx"])
    if rc1 == 0:
        logging.info("nginx успешно перезагружен (reload).")
        return

    logging.error("nginx reload не удался (rc=%s). Пытаюсь restart...\n%s", rc1, out1[:2000])
    rc2, out2 = run_cmd([systemctl_bin, "restart", "nginx"])
    if rc2 == 0:
        logging.info("nginx успешно перезапущен (restart).")
        return

    logging.critical("nginx restart тоже не удался (rc=%s):\n%s", rc2, out2[:2000])

def pick_cert_filename_for_nginx_target(nginx_cert_path: str) -> str:
    """
    Пытаемся понять, что именно ожидает путь ssl_certificate:
    - fullchain -> fullchain.pem
    - chain -> chain.pem
    - cert -> cert.pem
    - иначе -> fullchain.pem
    """
    b = os.path.basename(nginx_cert_path).lower()
    if "fullchain" in b:
        return "fullchain.pem"
    if "chain" in b:
        return "chain.pem"
    if "cert" in b:
        return "cert.pem"
    return "fullchain.pem"


def strip_nginx_comment(line: str) -> str:
    # Наивно (но обычно достаточно): режем всё после #, если это не внутри кавычек.
    # Для простоты игнорируем сложные случаи.
    if "#" not in line:
        return line
    in_s = False
    in_d = False
    res = []
    for ch in line:
        if ch == "'" and not in_d:
            in_s = not in_s
        elif ch == '"' and not in_s:
            in_d = not in_d
        if ch == "#" and not in_s and not in_d:
            break
        res.append(ch)
    return "".join(res)

def infer_domain_from_path(cert_path: str) -> Optional[str]:
    # очень грубо: берём имя папки над файлом (часто /etc/nginx/ssl/example.com/fullchain.pem)
    try:
        p = os.path.abspath(cert_path)
        parent = os.path.basename(os.path.dirname(p))
        if "." in parent:
            return parent.lower()
    except Exception:
        pass
    return None
