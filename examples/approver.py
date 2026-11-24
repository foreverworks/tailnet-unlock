#!/usr/bin/env -S python3 -I
"""An example approver for a service of your own: approver.py <url> [poll seconds]

`deliver` runs it with one approval request on stdin and takes one response from its stdout. This
one asks an HTTPS service that shows requests to people:

  POST   <url>               the request, as it came on stdin
  GET    <url>/<request_id>  {"decision": "pending"}, or a decision: "approve" or "refuse", with
                             "by", an optional "note" and, for a recovery door that the person
                             confirmed separately, "recovery_acknowledged": true
  DELETE <url>/<request_id>  nobody waits for the answer any more

Anything unexpected ends it with exit code 1 and no output, which `deliver` takes as a refusal.
When the approval times out or `deliver` is stopped, this gets SIGTERM and takes its request back.
Adapt it to your service: the login it needs, and who may approve, are yours to add. Standard
library only.
"""

import json
import signal
import sys
import time
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from typing import NoReturn

TIMEOUT = 15
MAX_REPLY = 65536


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_: object) -> None:
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def call(method: str, url: str, body: bytes | None = None) -> dict[str, object]:
    request = urllib.request.Request(  # noqa: S310  # main() checked the scheme
        url, data=body, method=method, headers={"Content-Type": "application/json"}
    )
    with _OPENER.open(request, timeout=TIMEOUT) as reply:
        value: object = json.loads(reply.read(MAX_REPLY) or b"{}")
    if not isinstance(value, dict):
        raise ValueError("the service did not answer with a JSON object")
    return {str(key): item for key, item in value.items()}


def stop(signum: int, frame: object) -> NoReturn:
    del frame
    signal.signal(signum, signal.SIG_IGN)
    raise SystemExit(128 + signum)


def decide(url: str, request: dict[str, object], raw: bytes, poll: float) -> dict[str, object]:
    request_id = str(request["request_id"])
    expires = datetime.strptime(str(request["expires_at"]), "%Y-%m-%dT%H:%M:%SZ")
    mine = f"{url}/{urllib.parse.quote(request_id, safe='')}"
    decided = False
    try:
        call("POST", url, raw)
        while datetime.now(UTC) < expires.replace(tzinfo=UTC):
            answer = call("GET", mine)
            if answer.get("decision") in {"approve", "refuse"}:
                decided = True
                kept = ("decision", "by", "note", "recovery_acknowledged")
                return {
                    "schema": "tailnet-unlock.approval-response/1",
                    "request_id": request_id,
                    **{key: answer[key] for key in kept if key in answer},
                }
            if answer.get("decision") != "pending":
                raise ValueError("the service answered neither a decision nor pending")
            time.sleep(poll)
        raise ValueError("no decision in time")
    finally:
        if not decided:
            call("DELETE", mine)


def main(argv: list[str]) -> int:
    url = argv[1].rstrip("/")
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" and parts.hostname not in {"127.0.0.1", "::1"}:
        print("approver: the service's URL must be https", file=sys.stderr)
        return 1
    signal.signal(signal.SIGTERM, stop)
    raw = sys.stdin.buffer.read()
    try:
        request: object = json.loads(raw)
        if not isinstance(request, dict):
            raise ValueError("stdin holds no request")
        response = decide(url, request, raw, float(argv[2]) if len(argv) > 2 else 3.0)
    except (OSError, ValueError, KeyError) as error:
        print(f"approver: {error}", file=sys.stderr)
        return 1
    print(json.dumps(response))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
