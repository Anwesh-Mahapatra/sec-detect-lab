"""
Shared HTTP session.

Python 3.14 with Debian's system urllib3 hangs on gzip responses that carry no
Content-Length - which is exactly what OpenSearch sends. Identity encoding
returns in 10 ms; gzip never returns at all.

Every tool imports `session` from here so the workaround lives in one place.
"""

import requests

session = requests.Session()
session.headers.update({"Accept-Encoding": "identity"})
