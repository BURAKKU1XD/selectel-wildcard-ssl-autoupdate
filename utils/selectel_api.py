# -------------------------
# Selectel IAM token (project scoped)
# -------------------------
import json
import logging
from typing import List, Tuple, Optional

from utils.formatters import join_url
from utils.network import http_request
from utils.parsers import json_loads_safe, extract_private_key, extract_pem_certificates


def get_selectel_project_token(
    identity_url: str,
    username: str,
    account_id: str,
    password: str,
    project_name: str,
    timeout: int,
) -> str:
    url = join_url(identity_url, "auth/tokens")
    payload = {
        "auth": {
            "identity": {
                "methods": ["password"],
                "password": {
                    "user": {
                        "name": username,
                        "domain": {"name": account_id},
                        "password": password,
                    }
                },
            },
            "scope": {"project": {"name": project_name, "domain": {"name": account_id}}},
        }
    }
    data = json.dumps(payload).encode("utf-8")

    status, headers, body = http_request(
        "POST",
        url,
        headers={"Content-Type": "application/json"},
        data=data,
        timeout=timeout,
    )

    if status != 201:
        j = json_loads_safe(body)
        raise RuntimeError(f"Не удалось получить IAM-токен проекта. HTTP {status}. Ответ: {j or body[:500]}")

    # Заголовок может быть в разном регистре
    token = headers.get("X-Subject-Token") or headers.get("x-subject-token")
    if not token:
        raise RuntimeError("IAM-токен не найден в заголовке X-Subject-Token.")
    return token


# -------------------------
# Selectel Let's Encrypt certs list
# -------------------------
def list_selectel_le_certs(le_base_url: str, token: str, timeout: int) -> List[dict]:
    """
    Пытаемся поддержать два варианта:
      1) le_base_url = https://api.selectel.ru/certs/le   -> list на "/"
      2) le_base_url = https://api.selectel.ru            -> list на "/certs/le/"
    """
    candidates = [
        join_url(le_base_url, ""),          # "/"
        join_url(le_base_url, "certs/le/"), # на случай если base = https://api.selectel.ru
    ]

    last_err = None
    for url in candidates:
        status, _headers, body = http_request(
            "GET",
            url,
            headers={"X-Auth-Token": token},
            timeout=timeout,
        )
        if status == 200:
            j = json_loads_safe(body)
            if not isinstance(j, dict) or "items" not in j:
                raise RuntimeError(f"Неожиданный формат списка сертификатов: {j or body[:300]}")
            items = j.get("items") or []
            if not isinstance(items, list):
                raise RuntimeError(f"items не list: {type(items)}")
            return items

        last_err = f"GET {url} -> HTTP {status}: {body[:300]}"
        logging.warning("Не получилось взять список сертификатов по %s: HTTP %s", url, status)

    raise RuntimeError(f"Не удалось получить список LE сертификатов. Последняя ошибка: {last_err}")

def get_cert_manager_json(cert_manager_url: str, token: str, path: str, timeout: int) -> Tuple[int, object, bytes]:
    url = join_url(cert_manager_url, path)
    status, _headers, body = http_request(
        "GET",
        url,
        headers={"X-Auth-Token": token},
        timeout=timeout,
    )
    j = json_loads_safe(body)
    return status, j if j is not None else body.decode("utf-8", errors="replace"), body



def download_selectel_cert_bundle(
    cert_manager_url: str,
    token: str,
    cert_id: str,
    timeout: int,
) -> Tuple[List[str], str]:
    """
    Возвращает (cert_chain_list, private_key_pem)
    cert_chain_list: список PEM сертификатов (как минимум leaf).
    """
    certs: List[str] = []
    privkey: Optional[str] = None

    # 1) Пробуем /cert/{id} (часто там есть pem.certificates)
    status, obj, _raw = get_cert_manager_json(cert_manager_url, token, f"cert/{cert_id}", timeout)

    if status == 200:
        certs = extract_pem_certificates(obj)

    # 2) Пробуем /cert/{id}/ca_chain (если выше пусто)
    if not certs:
        status2, obj2, _raw2 = get_cert_manager_json(cert_manager_url, token, f"cert/{cert_id}/ca_chain", timeout)
        if status2 == 200:
            certs = extract_pem_certificates(obj2)

    # 3) private_key
    status3, obj3, raw3 = get_cert_manager_json(cert_manager_url, token, f"cert/{cert_id}/private_key", timeout)
    if status3 == 200:
        privkey = extract_private_key(obj3)
        if not privkey:
            # иногда может быть просто текстом
            txt = raw3.decode("utf-8", errors="replace")
            privkey = extract_private_key(txt)

    if not certs:
        raise RuntimeError(f"Не удалось получить публичные сертификаты для cert_id={cert_id}")
    if not privkey:
        raise RuntimeError(f"Не удалось получить private_key для cert_id={cert_id}")

    return certs, privkey
