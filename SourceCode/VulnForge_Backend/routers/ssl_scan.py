from fastapi import APIRouter
import subprocess
import json
import ssl
import socket
import datetime

router = APIRouter()

@router.get("/")
def ssl_scan(target: str):
    try:
        host = target.replace("https://", "").replace("http://", "").split("/")[0]

        # Try sslyze first (if installed)
        try:
            cmd = ["sslyze", "--json_out=-", host]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                server_results = data.get("server_scan_results", [])
                if server_results:
                    scan_result = server_results[0].get("scan_result", {})

                    # Extract certificate info
                    cert_info = {}
                    cert_data = scan_result.get("certificate_info", {})
                    if cert_data and "result" in cert_data:
                        deployments = cert_data["result"].get("certificate_deployments", [])
                        if deployments:
                            leaf = deployments[0].get("received_certificate_chain", [])
                            if leaf:
                                subj = leaf[0].get("subject", {})
                                cert_info = {
                                    "subject": str(subj),
                                    "issuer": str(leaf[0].get("issuer", "")),
                                    "not_before": str(leaf[0].get("not_valid_before", "")),
                                    "not_after": str(leaf[0].get("not_valid_after", "")),
                                    "serial_number": str(leaf[0].get("serial_number", "")),
                                }

                    # Extract TLS support
                    def get_cipher_status(key):
                        d = scan_result.get(key, {})
                        if not d or "result" not in d:
                            return "unknown"
                        accepted = d["result"].get("accepted_cipher_suites", [])
                        return f"{len(accepted)} ciphers accepted" if accepted else "rejected"

                    return {
                        "target": host,
                        "status": "success",
                        "certificate": cert_info if cert_info else {"common_name": host},
                        "tls_1_0": get_cipher_status("tls_1_0_cipher_suites"),
                        "tls_1_1": get_cipher_status("tls_1_1_cipher_suites"),
                        "tls_1_2": get_cipher_status("tls_1_2_cipher_suites"),
                        "tls_1_3": get_cipher_status("tls_1_3_cipher_suites"),
                    }
        except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError):
            pass

        # Fallback: Python ssl module
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(socket.socket(socket.AF_INET), server_hostname=host)
        conn.settimeout(10)
        conn.connect((host, 443))
        cert = conn.getpeercert()
        conn.close()

        subject = dict(x[0] for x in cert.get("subject", ()))
        issuer = dict(x[0] for x in cert.get("issuer", ()))

        return {
            "target": host,
            "status": "success",
            "certificate": {
                "common_name": subject.get("commonName", ""),
                "organization": subject.get("organizationName", ""),
                "issuer": issuer.get("organizationName", ""),
                "issuer_cn": issuer.get("commonName", ""),
                "not_before": cert.get("notBefore", ""),
                "not_after": cert.get("notAfter", ""),
                "serial_number": cert.get("serialNumber", ""),
                "version": cert.get("version", ""),
                "san": ", ".join([v for _, v in cert.get("subjectAltName", ())]),
            },
            "cert": {
                "common_name": subject.get("commonName", ""),
                "organization": subject.get("organizationName", ""),
                "issuer": issuer.get("organizationName", ""),
                "issuer_cn": issuer.get("commonName", ""),
                "not_before": cert.get("notBefore", ""),
                "not_after": cert.get("notAfter", ""),
                "serial_number": cert.get("serialNumber", ""),
                "san": ", ".join([v for _, v in cert.get("subjectAltName", ())]),
            },
        }

    except subprocess.TimeoutExpired:
        return {"status": "error", "message": "Scan timed out"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
