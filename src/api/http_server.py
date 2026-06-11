"""Minimal HTTP API server for the enterprise risk-assessment service.



Wraps ``RiskService`` with a stdlib HTTP interface (no extra dependencies).

Production deployments would use FastAPI/uvicorn behind a load balancer; this

server demonstrates the API contract and RBAC enforcement.



Endpoints:

  POST /v1/assessments     - submit assessment (JSON body + X-API-Key header)

  GET  /v1/assessments     - list assessments for tenant

  GET  /v1/assessments/{id} - get one assessment

  DELETE /v1/assessments/{id} - delete assessment

  GET  /v1/assessments/{id}/vex - OpenVEX export

  GET  /v1/audit           - tenant audit log

  GET  /health             - liveness

"""



from __future__ import annotations



import argparse

import json

import os

from http.server import BaseHTTPRequestHandler, HTTPServer

from typing import Any

from urllib.parse import urlparse



from src.api.authz import AuthenticationError, AuthorizationError

from src.api.service import RiskService



DEFAULT_KEYS = {

    "dev-owner-key": {"actor": "dev", "tenant": "default", "role": "owner"},

    "dev-viewer-key": {"actor": "viewer", "tenant": "default", "role": "viewer"},

}





class RiskAPIHandler(BaseHTTPRequestHandler):

    service: RiskService = None  # type: ignore



    def _read_json(self) -> dict[str, Any]:

        length = int(self.headers.get("Content-Length", 0))

        if length <= 0:

            return {}

        return json.loads(self.rfile.read(length).decode("utf-8"))



    def _api_key(self) -> str:

        return self.headers.get("X-API-Key", "")



    def _send(self, code: int, body: Any) -> None:

        payload = json.dumps(body, indent=2).encode("utf-8")

        self.send_response(code)

        self.send_header("Content-Type", "application/json")

        self.send_header("Content-Length", str(len(payload)))

        self.end_headers()

        self.wfile.write(payload)



    def do_GET(self) -> None:  # noqa: N802

        path = urlparse(self.path).path.rstrip("/") or "/"

        key = self._api_key()

        try:

            if path == "/health":

                self._send(200, {"status": "ok"})

                return

            if path == "/v1/assessments":

                self._send(200, {"assessments": self.service.list_assessments(key)})

                return

            if path == "/v1/audit":

                self._send(200, self.service.read_audit(key))

                return

            if path == "/v1/dashboard":
                from src.ml.data_flywheel import get_aggregate_stats
                self._send(200, {
                    "aggregate": get_aggregate_stats(),
                    "recent_assessments": self.service.list_assessments(key)[:10],
                })
                return

            if path.startswith("/v1/assessments/") and path.endswith("/vex"):

                scan_id = path.split("/")[3]

                self._send(200, self.service.get_vex(key, scan_id))

                return

            if path.startswith("/v1/assessments/"):

                scan_id = path.split("/")[-1]

                self._send(200, self.service.get_assessment(key, scan_id))

                return

            self._send(404, {"error": "not found"})

        except AuthenticationError as exc:

            self._send(401, {"error": str(exc)})

        except AuthorizationError as exc:

            self._send(403, {"error": str(exc)})

        except KeyError as exc:

            self._send(404, {"error": str(exc)})

        except Exception as exc:

            self._send(500, {"error": str(exc)})



    def do_POST(self) -> None:  # noqa: N802

        path = urlparse(self.path).path.rstrip("/")

        key = self._api_key()

        try:

            if path == "/v1/assessments":

                body = self._read_json()

                assessment = body.get("assessment") or body

                repo = body.get("repo", "")

                result = self.service.submit_assessment(key, assessment, repo=repo)

                self._send(201, result)

                return

            self._send(404, {"error": "not found"})

        except AuthenticationError as exc:

            self._send(401, {"error": str(exc)})

        except AuthorizationError as exc:

            self._send(403, {"error": str(exc)})

        except Exception as exc:

            self._send(500, {"error": str(exc)})



    def do_DELETE(self) -> None:  # noqa: N802

        path = urlparse(self.path).path.rstrip("/")

        key = self._api_key()

        try:

            if path.startswith("/v1/assessments/"):

                scan_id = path.split("/")[-1]

                self.service.delete_assessment(key, scan_id)

                self._send(204, {})

                return

            self._send(404, {"error": "not found"})

        except AuthenticationError as exc:

            self._send(401, {"error": str(exc)})

        except AuthorizationError as exc:

            self._send(403, {"error": str(exc)})

        except KeyError as exc:

            self._send(404, {"error": str(exc)})

        except Exception as exc:

            self._send(500, {"error": str(exc)})



    def log_message(self, fmt: str, *args: Any) -> None:

        return  # quiet default





def run_server(host: str = "127.0.0.1", port: int = 8080, data_dir: str = "data/api") -> None:

    os.makedirs(data_dir, exist_ok=True)

    service = RiskService(data_dir, DEFAULT_KEYS)

    RiskAPIHandler.service = service

    httpd = HTTPServer((host, port), RiskAPIHandler)

    print(f"Risk API listening on http://{host}:{port}  (data_dir={data_dir})")

    httpd.serve_forever()





def main() -> None:

    parser = argparse.ArgumentParser(description="PRAS HTTP API server")

    parser.add_argument("--host", default="127.0.0.1")

    parser.add_argument("--port", type=int, default=8080)

    parser.add_argument("--data-dir", default="data/api")

    args = parser.parse_args()

    run_server(args.host, args.port, args.data_dir)





if __name__ == "__main__":

    main()


