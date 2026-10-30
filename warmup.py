# Fills the decision cache for the stable core dossiers (no grader check used).
# Usage: python3 warmup.py https://safe-ai-mailroom-03w8.onrender.com/v1/mailroom/actions raw.json
import json, sys, time, urllib.request
url, path = sys.argv[1], sys.argv[2]
dossiers = json.load(open(path))
body = {"profile": "ga5-mailroom-action-gate/v2", "operation": "propose", "warmup": True,
        "evaluationId": "warm-%d" % int(time.time()),
        "receiptVerifier": {"algorithm": "Ed25519", "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}},
        "allowedActions": ["create_draft", "update_internal_record", "send_approved_notice", "request_confirmation", "quarantine_item", "no_action"],
        "dossiers": dossiers}
t = time.time()
req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
r = json.load(urllib.request.urlopen(req, timeout=150))
counts = {}
for p in r["proposals"]:
    counts[p["action"]] = counts.get(p["action"], 0) + 1
print("done in %.1fs" % (time.time() - t)); print(counts)
