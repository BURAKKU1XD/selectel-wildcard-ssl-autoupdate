import logging
import re
from datetime import datetime
from typing import Optional, List

from utils.cmd import run_cmd


# -------------------------
# openssl helpers
# -------------------------
def get_cert_not_after(cert_path: str) -> Optional[datetime]:
    rc, out = run_cmd(["openssl", "x509", "-enddate", "-noout", "-in", cert_path])
    if rc != 0:
        logging.warning("openssl не смог прочитать сертификат: %s\n%s", cert_path, out[:500])
        return None
    # notAfter=May  5 12:00:00 2026 GMT
    m = re.search(r"notAfter=(.+)", out)
    if not m:
        return None
    val = m.group(1).strip()
    try:
        # %d может быть с двойным пробелом (May__5)
        val = re.sub(r"\s+", " ", val)
        return datetime.strptime(val, "%b %d %H:%M:%S %Y %Z")
    except Exception:
        return None

def get_cert_san_domains(cert_path: str) -> List[str]:
    rc, out = run_cmd(["openssl", "x509", "-noout", "-ext", "subjectAltName", "-in", cert_path])
    if rc != 0:
        return []
    dns = re.findall(r"DNS:([^,\s]+)", out)
    return [d.strip().lower().strip(".") for d in dns if d.strip()]
