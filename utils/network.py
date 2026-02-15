import urllib.error
import urllib.request

from typing import Optional, Dict, Tuple

# -------------------------
# HTTP helper
# -------------------------
def http_request(
    method: str,
    url: str,
    headers: Optional[Dict[str, str]] = None,
    data: Optional[bytes] = None,
    timeout: int = 30,
) -> Tuple[int, Dict[str, str], bytes]:
    req = urllib.request.Request(url=url, data=data, method=method.upper())
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
            hdrs = {k: v for k, v in resp.getheaders()}
            return resp.getcode(), hdrs, body
    except urllib.error.HTTPError as e:
        body = e.read() if hasattr(e, "read") else b""
        hdrs = {k: v for k, v in e.headers.items()} if e.headers else {}
        return e.code, hdrs, body
    except Exception as e:
        raise RuntimeError(f"HTTP запрос упал: {method} {url}: {e}") from e
