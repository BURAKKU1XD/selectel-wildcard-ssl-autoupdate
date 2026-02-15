import re
from datetime import datetime
import json
from typing import List, Dict, Optional

from utils.openssl import get_cert_san_domains


def parse_selectel_date(s: str):
    if not s or not isinstance(s, str):
        return None

    # ISO 8601 с UTC (Z)
    try:
        if s.endswith("Z"):
            return datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        pass

    # ISO 8601 без микросекунд
    try:
        if s.endswith("Z"):
            return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        pass

    # Старый формат из документации
    fmts = [
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
    ]

    for fmt in fmts:
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            pass

    return None

def parse_domain_base(d: str):
    d = (d or "").strip().lower().strip(".")
    if d.startswith("*."):
        d = d[2:]
    return d

def json_loads_safe(data):
    if not data:
        return None

    try:
        if isinstance(data, bytes):
            data = data.decode("utf-8-sig")
        elif not isinstance(data, str):
            return None

        return json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None

def build_latest_cert_map(items: List[dict]) -> Dict[str, dict]:
    """
    Возвращает {base_domain: item} с максимальным expire_at.
    """
    best: Dict[str, dict] = {}

    for item in items:
        domains = item.get("domains") or []
        exp = parse_selectel_date(item.get("expire_at") or "")
        if not exp:
            continue

        for dom in domains:
            b = parse_domain_base(dom)
            if not b:
                continue
            cur = best.get(b)
            if (cur is None) or (parse_selectel_date(cur.get("expire_at") or "") or datetime.min) < exp:
                best[b] = item

    return best

def extract_private_key(obj: object) -> Optional[str]:
    if isinstance(obj, dict):
        for k in ("private_key", "key", "data"):
            v = obj.get(k)
            if isinstance(v, str) and "BEGIN" in v:
                return v.strip() + "\n"
    if isinstance(obj, str) and "BEGIN" in obj:
        return obj.strip() + "\n"
    return None

def infer_domain_from_cert(cert_path: str) -> Optional[str]:
    dns = get_cert_san_domains(cert_path)
    if dns:
        # предпочитаем wildcard, иначе первый
        wild = [d for d in dns if d.startswith("*.")]
        pick = wild[0] if wild else dns[0]
        return parse_domain_base(pick)
    return None

def split_pem_chain(text: str) -> List[str]:
    # Разрезаем на блоки -----BEGIN CERTIFICATE----- ... -----END CERTIFICATE-----
    blocks = re.findall(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
        text,
        flags=re.DOTALL,
    )
    return [b.strip() + "\n" for b in blocks]

def extract_pem_certificates(obj: object) -> List[str]:
    """
    Пытаемся достать список PEM сертификатов из разных возможных форматов ответа.
    """
    certs: List[str] = []

    if isinstance(obj, dict):
        # Варианты: {"pem":{"certificates":[...]}}, {"certificates":[...]}, {"items":[...]} и т.п.
        if isinstance(obj.get("pem"), dict) and isinstance(obj["pem"].get("certificates"), list):
            certs = [c for c in obj["pem"]["certificates"] if isinstance(c, str) and c.strip()]
        elif isinstance(obj.get("certificates"), list):
            certs = [c for c in obj["certificates"] if isinstance(c, str) and c.strip()]
        elif isinstance(obj.get("certificate"), str) and obj["certificate"].strip():
            certs = [obj["certificate"]]
        elif isinstance(obj.get("data"), str) and "BEGIN CERTIFICATE" in obj["data"]:
            certs = split_pem_chain(obj["data"])

    elif isinstance(obj, str):
        if "BEGIN CERTIFICATE" in obj:
            certs = split_pem_chain(obj)

    return certs

