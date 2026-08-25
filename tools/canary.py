#!/usr/bin/env python3
"""
Pipeline heartbeat generator.

Performs one benign, uniquely-named write against the k3s API every run. The
write is guaranteed to be audited, so its arrival in OpenSearch proves the whole
transport is alive: apiserver -> audit.log -> Fluent Bit -> Kafka -> Cribl ->
OpenSearch. PIPELINE_CANARY alerts when it stops arriving.

  create configmap detection-canary/canary-<epoch>   then delete it

WHY A CONFIGMAP WRITE, AND NOT SOMETHING HARDER TO SILENCE
----------------------------------------------------------
The audit policy is first-match-wins. A configmap write by a normal user falls
through to the generic write rule near the bottom:

  1  pods/exec, pods/attach, pods/portforward   RequestResponse   no match
  2  secrets, serviceaccounts/token             Metadata          no match
  3  rbac.authorization.k8s.io/*                RequestResponse   no match
  4  level: None  groups system:nodes, system:serviceaccounts:kube-system
  5  level: None  users  apiserver, scheduler, controller-manager
  6  level: Metadata  verbs create/update/patch/delete             <-- MATCH
  7  level: None  verbs get/list/watch

An RBAC object would match rule 3, which sits ABOVE the two `level: None` drops
and is therefore strictly harder to silence. That is exactly why it is the wrong
choice: a canary riding a more privileged path than the traffic it vouches for
can stay green while the general write path has gone blind. Rule 6 is where
ordinary cluster writes live, so the canary shares their fate. Reads are not an
option at all - rule 7 drops them (FINDINGS A3).

Consequence worth knowing: rule 6 sits BELOW the `level: None` rules, so this
canary goes dark if its identity is ever moved into system:nodes or
system:serviceaccounts:kube-system. That direction is safe - it produces a false
alarm, never false confidence - and it makes the canary sensitive to the policy
ordering regressions in FINDINGS A1.

Metadata level keeps objectRef but drops requestObject, so the unique tag has to
live in the object NAME. Labels would not survive.

Create AND delete emit two events per beat: redundancy if one is lost, and the
namespace stays clean.

THE STATE FILE
--------------
Also touches --state-file on success. Without it, "the generator stopped" and
"the transport stopped" are the same observation - no heartbeat in the index -
and they need opposite responses. The file's mtime is written by this tool
before the pipeline is involved at all, so run_detections.py can tell them
apart: fresh file + no heartbeat means transport; stale file means this tool
(or its cron) is not running.

  crontab:  */5 * * * * cd /path/to/sec-detect-lab && uv run python tools/canary.py

Exit codes:
  0  heartbeat written
  1  the write failed - the apiserver rejected it or kubectl is unusable
  2  usage error
"""

import argparse
import shutil
import subprocess
import sys
import time
from pathlib import Path

NAMESPACE = "detection-canary"
PREFIX = "canary-"
DEFAULT_STATE = Path.home() / ".cache" / "sec-detect-lab" / "canary.state"


def kubectl(*args: str, timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["kubectl", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def ensure_namespace(ns: str) -> None:
    """Create the namespace if absent. Idempotent, and safe to race."""
    if kubectl("get", "namespace", ns).returncode == 0:
        return
    r = kubectl("create", "namespace", ns)
    # A parallel run may have won; that is success, not failure.
    if r.returncode != 0 and "already exists" not in r.stderr:
        raise RuntimeError(f"cannot create namespace {ns}: {r.stderr.strip()}")


def sweep(ns: str) -> int:
    """Delete leftover canary configmaps from runs that died before cleanup."""
    r = kubectl("-n", ns, "get", "configmap",
                "-o", "jsonpath={range .items[*]}{.metadata.name}{\"\\n\"}{end}")
    if r.returncode != 0:
        return 0
    stale = [n for n in r.stdout.split() if n.startswith(PREFIX)]
    for name in stale:
        kubectl("-n", ns, "delete", "configmap", name, "--ignore-not-found")
    return len(stale)


def beat(ns: str) -> str:
    """One heartbeat: create then delete a uniquely-named configmap."""
    name = f"{PREFIX}{int(time.time())}"
    r = kubectl("-n", ns, "create", "configmap", name, "--from-literal=probe=1")
    if r.returncode != 0:
        raise RuntimeError(f"create {name} failed: {r.stderr.strip()}")
    try:
        # The delete is a second audited write, so a lost create still leaves a
        # heartbeat. Failure to clean up is not failure to beat - --sweep will
        # collect it later - so this never raises.
        kubectl("-n", ns, "delete", "configmap", name, "--ignore-not-found")
    except Exception:  # noqa: BLE001
        pass
    return name


def touch(state_file: Path) -> None:
    """Record that the generator ran. Written before the pipeline is involved."""
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_text(f"{time.time():.0f}\n")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--namespace", default=NAMESPACE)
    ap.add_argument("--state-file", type=Path, default=DEFAULT_STATE,
                    help=f"touched on success (default: {DEFAULT_STATE})")
    ap.add_argument("--sweep", action="store_true",
                    help="delete leftover canary configmaps, then beat")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    if shutil.which("kubectl") is None:
        print("canary: kubectl not on PATH", file=sys.stderr)
        return 1

    try:
        ensure_namespace(args.namespace)
        if args.sweep:
            n = sweep(args.namespace)
            if n and not args.quiet:
                print(f"swept {n} leftover canary configmap(s)")
        name = beat(args.namespace)
    except (RuntimeError, subprocess.TimeoutExpired, OSError) as exc:
        # No state-file touch here: the generator ran but produced no heartbeat,
        # and claiming otherwise would mask a real outage as a transport fault.
        print(f"canary: {exc}", file=sys.stderr)
        return 1

    touch(args.state_file)
    if not args.quiet:
        print(f"heartbeat {args.namespace}/{name}  state={args.state_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
