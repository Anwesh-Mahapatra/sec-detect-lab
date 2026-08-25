"""
Shared HTTP session.

OpenSearch returns `_search` as gzip with `Transfer-Encoding: chunked` and no
Content-Length. On one lab machine - Debian's system Python with Debian's
patched urllib3 - reading that response never returns. Identity encoding comes
back in milliseconds. Every tool imports `session` from here so the workaround
lives in one place.

RETAINED DELIBERATELY. The project now pins Python 3.12 with urllib3 from PyPI
via uv.lock, and the hang does not reproduce on any PyPI build tested
(3.12/3.13/3.14 x urllib3 2.0.7/2.7.0, up to multi-MB chunked responses). But
non-reproduction is not proof of absence: the trigger was never isolated to a
specific urllib3 version, only to that host's packaging of it. The workaround
also still covers `python3 tools/run_detections.py` run outside uv, which is
the exact invocation that hit the bug in the first place.

Cost is one request header. Full test matrix and reasoning: FINDINGS D1.
"""

import requests

session = requests.Session()
session.headers.update({"Accept-Encoding": "identity"})
