#!/usr/bin/env python3
"""Runs an OpenID Foundation conformance suite test plan against ShieldGate.

A minimal client of the suite's REST API (standard library only): it creates
the plan, runs every module one after another, waits for each to finish and
prints a summary. The suite itself drives the browser (login and consent)
from the "browser" section of the configuration.

    run_plan.py SUITE_URL PLAN_NAME VARIANT_JSON CONFIG_FILE [RESULTS_JSON]

Exit status: 0 when no module FAILED, 1 otherwise.
"""
import json
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# The locally run suite serves a self-signed certificate
CONTEXT = ssl.create_default_context()
CONTEXT.check_hostname = False
CONTEXT.verify_mode = ssl.CERT_NONE

MODULE_TIMEOUT = 300


def api(base, method, path, params=None, body=None):
    url = base + path + ("?" + urllib.parse.urlencode(params) if params else "")
    headers = {"Content-Type": "application/json"} if body is not None else {}
    request = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, context=CONTEXT, timeout=60) as resp:
            text = resp.read().decode()
    except urllib.error.HTTPError as e:
        raise SystemExit(f"{method} {path} failed: HTTP {e.code} {e.read().decode()[:300]}")
    return json.loads(text) if text else None


def wait_finished(base, module_id):
    """Waits until the module finishes. A module whose checks are done but
    that waits for a person to upload a screenshot (result REVIEW) counts as
    done: the screenshot is only needed for certification."""
    deadline = time.time() + MODULE_TIMEOUT
    while time.time() < deadline:
        info = api(base, "GET", f"api/info/{module_id}")
        if info["status"] in ("FINISHED", "INTERRUPTED"):
            return info
        if info["status"] == "WAITING" and info.get("result") == "REVIEW":
            return info
        if info["status"] == "CONFIGURED":
            api(base, "POST", f"api/runner/{module_id}")
        time.sleep(1)
    return api(base, "GET", f"api/info/{module_id}")


def failures(base, module_id):
    """The conditions a module reported as FAILURE or WARNING"""
    out = []
    for entry in api(base, "GET", f"api/log/{module_id}") or []:
        if entry.get("result") in ("FAILURE", "WARNING"):
            out.append(f"{entry['result']}: {entry.get('src', '')}: {entry.get('msg', '')}")
    return out


def main():
    if len(sys.argv) < 5:
        raise SystemExit(__doc__)
    base, plan_name, variant, config_file = sys.argv[1:5]
    results_file = sys.argv[5] if len(sys.argv) > 5 else None
    base = base.rstrip("/") + "/"
    with open(config_file, "rb") as f:
        config = f.read()

    plan = api(base, "POST", "api/plan", {"planName": plan_name, "variant": variant}, config)
    print(f"plan {plan['id']}: {base}plan-detail.html?plan={plan['id']}")

    results = []
    for module in plan["modules"]:
        name = module["testModule"]
        params = {"test": name, "plan": plan["id"]}
        if module.get("variant"):
            params["variant"] = json.dumps(module["variant"])
        created = api(base, "POST", "api/runner", params)
        info = wait_finished(base, created["id"])
        result = info.get("result") or info["status"]
        problems = failures(base, created["id"]) if result not in ("PASSED", "REVIEW") else []
        results.append({"module": name, "id": created["id"], "result": result, "problems": problems})
        print(f"{result:<9} {name}", flush=True)
        for p in problems:
            print(f"          {p}", flush=True)

    counts = {}
    for r in results:
        counts[r["result"]] = counts.get(r["result"], 0) + 1
    print("summary: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    if results_file:
        with open(results_file, "w") as f:
            json.dump({"plan": plan["id"], "plan_name": plan_name, "variant": json.loads(variant), "results": results}, f, indent=2)
    sys.exit(1 if counts.get("FAILED") else 0)


if __name__ == "__main__":
    main()
