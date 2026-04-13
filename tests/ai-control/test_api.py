#!/usr/bin/env python3
"""
AI Control Daemon - API endpoint smoke tests.

Tests basic endpoint availability and response structure.
Requires the daemon to be running on localhost:8420.

Usage: python test_api.py [--host HOST] [--port PORT]
"""

import json
import sys
import urllib.request
import urllib.error

HOST = "127.0.0.1"
PORT = 8420
passed = 0
failed = 0


def test(name, method, path, expected_status=200, body=None):
    global passed, failed
    url = f"http://{HOST}:{PORT}{path}"
    print(f"  {name:50s}", end=" ")

    try:
        data = json.dumps(body).encode() if body else None
        headers = {"Content-Type": "application/json"} if body else {}
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        resp = urllib.request.urlopen(req, timeout=10)
        status = resp.status

        if status == expected_status:
            print(f"\033[32mPASS\033[0m ({status})")
            passed += 1
        else:
            print(f"\033[31mFAIL\033[0m (got {status}, expected {expected_status})")
            failed += 1
    except urllib.error.HTTPError as e:
        if e.code == expected_status:
            print(f"\033[32mPASS\033[0m ({e.code})")
            passed += 1
        else:
            print(f"\033[31mFAIL\033[0m (got {e.code}, expected {expected_status})")
            failed += 1
    except Exception as e:
        print(f"\033[31mFAIL\033[0m ({e})")
        failed += 1


def main():
    global HOST, PORT

    for i, arg in enumerate(sys.argv):
        if arg == "--host" and i + 1 < len(sys.argv):
            HOST = sys.argv[i + 1]
        elif arg == "--port" and i + 1 < len(sys.argv):
            PORT = int(sys.argv[i + 1])

    print(f"=== AI Control Daemon API Tests ({HOST}:{PORT}) ===\n")

    # Check connectivity
    try:
        urllib.request.urlopen(f"http://{HOST}:{PORT}/health", timeout=5)
    except Exception as e:
        print(f"Cannot connect to daemon at {HOST}:{PORT}: {e}")
        print("Is the AI control daemon running?")
        sys.exit(1)

    print("-- Health --")
    test("GET /health", "GET", "/health")

    print("\n-- System --")
    test("GET /system/info", "GET", "/system/info")
    test("GET /system/processes", "GET", "/system/processes")

    print("\n-- Screen --")
    test("GET /screen/size", "GET", "/screen/size")
    test("GET /screen/capture/base64", "GET", "/screen/capture/base64")

    print("\n-- Network --")
    test("GET /network/ip", "GET", "/network/ip")
    test("GET /network/dns", "GET", "/network/dns")
    test("GET /network/routes", "GET", "/network/routes")

    print("\n-- Firewall --")
    test("GET /firewall/status", "GET", "/firewall/status")

    print("\n-- Services --")
    test("GET /services", "GET", "/services")

    print("\n-- Windows Services --")
    test("GET /win-services", "GET", "/win-services")
    test("GET /win-services-scm/status", "GET", "/win-services-scm/status")

    print("\n-- Trust System --")
    test("GET /trust/subjects", "GET", "/trust/subjects")
    test("GET /trust/anomalies", "GET", "/trust/anomalies")
    test("GET /trust/architecture", "GET", "/trust/architecture")

    print("\n-- Audit --")
    test("GET /audit/recent", "GET", "/audit/recent")

    print("\n-- Auth Token --")
    test("POST /auth/token", "POST", "/auth/token",
         body={"subject_id": 1, "name": "test-agent", "trust_level": 1})

    print("\n-- Keyboard (smoke) --")
    test("POST /keyboard/type", "POST", "/keyboard/type",
         body={"text": ""})  # Empty text, should succeed

    print(f"\n=== Results: {passed} passed, {failed} failed ===")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
