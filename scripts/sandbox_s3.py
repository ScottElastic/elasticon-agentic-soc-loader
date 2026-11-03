#!/usr/bin/env python3
"""An S3 server inside the sandbox's k3s cluster, plus a tiny stdlib S3 client.

Why: the GuardDuty archive is the "read it in place from S3" beat of the federation lab. In a
sandbox there is no AWS account and no key we could safely hand out, so the archive lives on an
S3-compatible server (SeaweedFS) running next to Elasticsearch. Elasticsearch reads it through
`http://s3.default.svc:9000` with `auth: none`: no credential exists anywhere.

    python3 scripts/sandbox_s3.py up       # deploy + wait until ready (idempotent)
    python3 scripts/sandbox_s3.py status
    python3 scripts/sandbox_s3.py down

Verified in an Instruqt sandbox (Elastic 9.5.2, ECK on k3s): pod ready in ~18 s, objects PUT with
SigV4, and `FROM <dataset>` read them through ES|QL data federation. MinIO (images pulled from
quay.io and Docker Hub) and moto (Elasticsearch gets 403/EOF reading from it) did NOT work.

Image tags are pinned and tried in order; third-party tags can vanish (MinIO's did).
"""
from __future__ import annotations

import datetime
import hashlib
import hmac
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

IMAGES = ["docker.io/chrislusf/seaweedfs:4.52", "docker.io/chrislusf/seaweedfs:4.51",
          "docker.io/chrislusf/seaweedfs:latest"]
NAMESPACE = "default"
NAME = "s3"
PORT = 9000
NODEPORT = 30900                                         # same server, reachable from the VM (no kubectl needed)
ENDPOINT = f"http://{NAME}.{NAMESPACE}.svc:{PORT}"      # what Elasticsearch (inside k8s) connects to
REGION = "us-east-1"                                     # arbitrary: the server does not care
DUMMY_USER = DUMMY_PASS = "vgi-local"                    # SigV4 needs *some* key; auth is open


def sh(cmd: str, stdin: str | None = None, timeout: int = 300) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, shell=True, input=stdin, capture_output=True, text=True, timeout=timeout)


def _manifest(image: str) -> str:
    return f"""
apiVersion: apps/v1
kind: Deployment
metadata: {{name: {NAME}, namespace: {NAMESPACE}, labels: {{app: {NAME}, managed-by: vgi-loader}}}}
spec:
  replicas: 1
  selector: {{matchLabels: {{app: {NAME}}}}}
  template:
    metadata: {{labels: {{app: {NAME}}}}}
    spec:
      containers:
      - name: weed
        image: {image}
        args: ["server", "-s3", "-s3.port={PORT}", "-dir=/data", "-master.volumeSizeLimitMB=128", "-volume.max=0"]
        ports: [{{containerPort: {PORT}}}]
        readinessProbe: {{tcpSocket: {{port: {PORT}}}, periodSeconds: 3}}
        resources: {{requests: {{memory: 256Mi, cpu: 100m}}}}
---
apiVersion: v1
kind: Service
metadata: {{name: {NAME}, namespace: {NAMESPACE}}}
spec:
  type: NodePort
  selector: {{app: {NAME}}}
  ports: [{{port: {PORT}, targetPort: {PORT}, nodePort: {NODEPORT}}}]
"""


def reachable(host: str = "127.0.0.1", port: int = NODEPORT) -> bool:
    try:
        socket.create_connection((host, port), timeout=2).close()
        return True
    except OSError:
        return False


def have_kubectl() -> bool:
    return sh("kubectl get ns default").returncode == 0


def is_ready() -> bool:
    """True when the S3 server answers on the VM's NodePort (works without kubectl)."""
    return reachable()


def ensure_server(log=print) -> bool:
    """Deploy the S3 server if it isn't running (needs kubectl, i.e. root). True when it is ready to use."""
    if is_ready():
        log(f"  S3 server already running ({ENDPOINT})")
        return True
    if not have_kubectl():
        log("  ❌ the S3 server is not running and this user has no kubectl; the sandbox setup should have started it")
        return False
    for image in IMAGES:
        log(f"  starting S3 server: {image}")
        sh(f"kubectl delete deployment {NAME} -n {NAMESPACE} --ignore-not-found --wait=true")
        r = sh("kubectl apply -f -", stdin=_manifest(image))
        if r.returncode != 0:
            log(f"    apply failed: {r.stderr.strip()[:200]}")
            continue
        r = sh(f"kubectl rollout status deployment/{NAME} -n {NAMESPACE} --timeout=150s", timeout=200)
        if "successfully rolled out" in r.stdout:
            for _ in range(30):                 # the S3 port opens a few seconds after the pod is Ready
                if reachable():
                    log(f"  S3 server ready ({image})")
                    return True
                time.sleep(2)
        log(f"    not ready: {(r.stdout + r.stderr).strip()[-160:]}")
    log("  ❌ no S3 server image could be started")
    return False


def stop_server() -> None:
    sh(f"kubectl delete deployment/{NAME} service/{NAME} -n {NAMESPACE} --ignore-not-found")


class S3:
    """Path-style S3 over plain HTTP from the VM to the server's NodePort (SigV4, dummy key)."""

    def __init__(self, hostport: str | None = None):
        self.hostport = hostport or f"127.0.0.1:{NODEPORT}"

    def _request(self, method: str, path: str, query: str = "", body: bytes = b""):
        now = datetime.datetime.now(datetime.timezone.utc)
        amz, ds = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
        payload = hashlib.sha256(body).hexdigest()
        headers = {"host": self.hostport, "x-amz-content-sha256": payload, "x-amz-date": amz}
        signed = ";".join(sorted(headers))
        canon = (f"{method}\n{urllib.parse.quote(path)}\n{query}\n"
                 + "".join(f"{k}:{headers[k]}\n" for k in sorted(headers)) + f"\n{signed}\n{payload}")
        scope = f"{ds}/{REGION}/s3/aws4_request"
        to_sign = f"AWS4-HMAC-SHA256\n{amz}\n{scope}\n{hashlib.sha256(canon.encode()).hexdigest()}"
        key = ("AWS4" + DUMMY_PASS).encode()
        for part in (ds, REGION, "s3", "aws4_request"):
            key = hmac.new(key, part.encode(), hashlib.sha256).digest()
        sig = hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()
        url = f"http://{self.hostport}{urllib.parse.quote(path)}" + (f"?{query}" if query else "")
        req = urllib.request.Request(url, data=body or None, method=method, headers={
            "x-amz-content-sha256": payload, "x-amz-date": amz,
            "Authorization": (f"AWS4-HMAC-SHA256 Credential={DUMMY_USER}/{scope}, "
                              f"SignedHeaders={signed}, Signature={sig}")})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def make_bucket(self, bucket: str) -> None:
        status, body = self._request("PUT", f"/{bucket}")
        if status not in (200, 409):            # 409: already owned by us
            raise RuntimeError(f"create bucket {bucket}: HTTP {status} {body[:120]!r}")

    def put(self, bucket: str, key: str, data: bytes, attempts: int = 6) -> None:
        """PUT with retries: a fresh SeaweedFS can answer 500 while it grows new volumes."""
        for n in range(1, attempts + 1):
            status, body = self._request("PUT", f"/{bucket}/{key}", body=data)
            if status == 200:
                return
            if status < 500 or n == attempts:
                raise RuntimeError(f"put {key}: HTTP {status} {body[:400]!r}")
            time.sleep(2 * n)

    def delete(self, bucket: str, key: str) -> None:
        self._request("DELETE", f"/{bucket}/{key}")

    def list(self, bucket: str, prefix: str = "") -> list[str]:
        keys, token = [], ""
        while True:
            q = "list-type=2&prefix=" + urllib.parse.quote(prefix, safe="")
            if token:
                q += "&continuation-token=" + urllib.parse.quote(token, safe="")
            q = "&".join(sorted(q.split("&")))      # SigV4 wants the canonical query sorted
            status, body = self._request("GET", f"/{bucket}", query=q)
            if status != 200:
                return keys
            root = ET.fromstring(body)
            ns = {"s": root.tag.split("}")[0].strip("{")} if "}" in root.tag else {}
            find = (lambda el, tag: el.findall(f"s:{tag}", ns)) if ns else (lambda el, tag: el.findall(tag))
            keys += [find(c, "Key")[0].text for c in find(root, "Contents")]
            trunc = find(root, "IsTruncated")
            nxt = find(root, "NextContinuationToken")
            if trunc and trunc[0].text == "true" and nxt:
                token = nxt[0].text
            else:
                return keys


def main() -> int:
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"
    if cmd == "up":
        return 0 if ensure_server() else 1
    if cmd == "down":
        stop_server()
        return 0
    print("ready" if is_ready() else "not running", ENDPOINT)
    return 0 if is_ready() else 1


if __name__ == "__main__":
    sys.exit(main())
