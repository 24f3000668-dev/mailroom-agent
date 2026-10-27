"""Simulated grader for the mailroom agent.
Usage: python mailroom_selftest.py http://localhost:8000/v1/mailroom/actions
(The AI part is not judged here; this checks protocol, signatures, replay, conflicts.)"""
import sys, json, base64, hashlib, uuid, threading
import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

URL = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000/v1/mailroom/actions"
P = "ga5-mailroom-action-gate/v2"
canon = lambda o: json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
sha = lambda s: hashlib.sha256(s.encode()).hexdigest()
OK = []
def check(name, cond, extra=""):
    OK.append(bool(cond)); print(("PASS  " if cond else "FAIL  ") + name + ("" if cond else "   <- " + str(extra)[:250]))
def post(b): return requests.post(URL, data=json.dumps(b), headers={"Content-Type": "application/json"})

def make_dossiers(tag, n=3):
    ds = []
    for i in range(n):
        ds.append({"dossierId": "d-%s-%d" % (tag, i), "partition": "stable_core", "receivedAt": "2026-10-01T10:00:00Z",
                   "mailbox": "support@example.test", "objective": "Handle the inbound message",
                   "sources": [{"sourceId": "s-%s-%d" % (tag, i), "kind": "email", "provenance": "external", "title": "Order question",
                                "lines": [{"lineId": "l-%s-%d-1" % (tag, i), "text": "Hi, where is order ORD-%d%d? From cust%d@example.test" % (i, i, i)},
                                          {"lineId": "l-%s-%d-2" % (tag, i), "text": "Order ORD-%d%d status is Shipped." % (i, i)}]}]})
    return ds

def new_eval():
    sk = Ed25519PrivateKey.generate()
    raw = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    x = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    eid = "ev-" + uuid.uuid4().hex[:10]
    return sk, eid, {"profile": P, "operation": "propose", "evaluationId": eid,
        "receiptVerifier": {"algorithm": "Ed25519", "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": x}},
        "corpus": {"coreId": "c", "auditId": "a", "stableCount": 3, "freshCount": 0},
        "allowedActions": ["create_draft", "update_internal_record", "send_approved_notice", "request_confirmation", "quarantine_item", "no_action"],
        "dossiers": make_dossiers(eid[3:])}

def pdigest(p):
    return sha(canon({"dossierId": p["dossierId"], "callId": p["callId"], "action": p["action"], "target": p.get("target"),
                      "payload": p["payload"], "evidence": sorted(p["evidence"])}))

def make_receipts(sk, eid, digest, proposals, accepted_flags):
    rs = []
    for p, acc in zip(proposals, accepted_flags):
        r = {"dossierId": p["dossierId"], "callId": p["callId"], "action": p["action"], "accepted": acc,
             "proposalDigest": pdigest(p), "receiptId": "rc-" + uuid.uuid4().hex}
        msg = canon({"profile": P, "evaluationId": eid, "inputDigest": digest, "receipt": r}).encode()
        r["receiptSignature"] = base64.b64encode(sk.sign(msg)).decode()
        rs.append(r)
    return rs

sk, eid, req = new_eval()
r = post(req); check("1 propose 200", r.status_code == 200, r.text)
resp = r.json()
check("2 content-type json", r.headers["Content-Type"].startswith("application/json"))
check("3 status awaiting_receipts + digest", resp["status"] == "awaiting_receipts" and resp["inputDigest"] == sha(canon(req["dossiers"])))
props = resp["proposals"]
check("4 one proposal per dossier, unique callIds", len(props) == 3 and len({p["callId"] for p in props}) == 3)
check("5 callId format", all(12 <= len(p["callId"]) <= 128 for p in props))
check("6 exact propose replay identical", post(req).text == r.text)
chg = json.loads(json.dumps(req)); chg["dossiers"][0]["objective"] = "changed"
check("7 changed content same evaluationId -> 409", post(chg).status_code == 409)
# same stable dossier in a NEW evaluation gets same callId
sk2, eid2, req2 = new_eval(); req2["dossiers"] = req["dossiers"]
r2 = post(req2).json()
check("8 stable dossier -> same callId across evaluations", [p["callId"] for p in r2["proposals"]] == [p["callId"] for p in props])

dig = resp["inputDigest"]
rcs = make_receipts(sk, eid, dig, props, [True, False, True])
base = {"profile": P, "operation": "commit", "evaluationId": eid, "inputDigest": dig}
bad = json.loads(json.dumps(rcs)); bad[0]["receiptSignature"] = bad[1]["receiptSignature"]
check("9 moved signature -> 400", post({**base, "receipts": bad}).status_code == 400)
other = Ed25519PrivateKey.generate()
forged = make_receipts(other, eid, dig, props, [True, True, True])
check("10 wrong-key signatures -> 400", post({**base, "receipts": forged}).status_code == 400)
tam = json.loads(json.dumps(rcs)); tam[1]["accepted"] = True
check("11 flipped accepted (signature breaks) -> 400", post({**base, "receipts": tam}).status_code == 400)
tam2 = json.loads(json.dumps(rcs)); tam2[0]["action"] = "no_action" if tam2[0]["action"] != "no_action" else "create_draft"
check("12 changed action -> 400", post({**base, "receipts": tam2}).status_code == 400)
check("13 missing receipt -> 400", post({**base, "receipts": rcs[:2]}).status_code == 400)
check("14 duplicate receipt -> 400", post({**base, "receipts": rcs[:2] + [rcs[0]]}).status_code == 400)
check("15 wrong digest -> 400", post({**base, "inputDigest": "0" * 64, "receipts": rcs}).status_code == 400)
check("16 unknown evaluation -> 4xx", 400 <= post({**base, "evaluationId": "nope", "receipts": rcs}).status_code < 500)
g = post({**base, "receipts": rcs}); check("17 valid commit 200 (after failed attempts)", g.status_code == 200, g.text)
out = g.json()
check("18 completed + statuses follow accepted", out["status"] == "completed" and [o["status"] for o in out["outcomes"]] == ["executed", "rejected", "executed"], out)
check("19 commit replay identical", post({**base, "receipts": rcs}).text == g.text)
rcs_b = make_receipts(sk, eid, dig, props, [False, False, False])
check("20 different commit after completion -> 409", post({**base, "receipts": rcs_b}).status_code == 409)

tam3 = json.loads(json.dumps(rcs)); tam3[0]["receiptSignature"] = tam3[1]["receiptSignature"]
check("20b tampered receipt AFTER completion -> 400 (not 409)", post({**base, "receipts": tam3}).status_code == 400)
for name, b, ok in [("21 bad profile", {**req, "profile": "x"}, (400, 422)),
                    ("22 bad operation", {**req, "operation": "zap"}, (400, 422)),
                    ("23 duplicate dossier ids", {**req, "evaluationId": "dup1", "dossiers": [req["dossiers"][0], req["dossiers"][0]]}, (400, 422)),
                    ("24 no dossiers", {**req, "evaluationId": "dup2", "dossiers": []}, (400, 422)),
                    ("25 missing verifier", {k: v for k, v in req.items() if k != "receiptVerifier"} | {"evaluationId": "dup3"}, (400, 422))]:
    check(name, post(b).status_code in ok)
check("26 non-JSON body -> 400", requests.post(URL, data="not json").status_code in (400, 422))

sk3, eid3, req3 = new_eval(); res = []
th = [threading.Thread(target=lambda: res.append(post(req3).text)) for _ in range(6)]
[t.start() for t in th]; [t.join() for t in th]
check("27 concurrent identical proposes -> identical", len(res) == 6 and len(set(res)) == 1)

# unit tests for the safety validator
import os; os.environ["DB_PATH"] = "/tmp/_unit.db"
sys.path.insert(0, "."); import mailroom_agent as m
d = req["dossiers"][0]; L1, L2 = d["sources"][0]["lines"][0]["lineId"], d["sources"][0]["lines"][1]["lineId"]
good = {"action": "create_draft", "target": {"kind": "draft_queue", "id": "mailbox:support@example.test"},
        "payload": {"recipient": "cust0@example.test", "referenceId": "ORD-00", "status": "Shipped", "template": "order_status"}, "evidence": [L2, L1]}
def rejects(x):
    try: m.validate(d, x); return False
    except ValueError: return True
check("U1 good draft accepted", m.validate(d, good)["evidence"] == sorted([L1, L2]))
check("U2 ungrounded value rejected", rejects({**good, "payload": {**good["payload"], "status": "Delivered"}}))
check("U3 extra payload key rejected", rejects({**good, "payload": {**good["payload"], "body": "hi"}}))
check("U4 unknown line rejected", rejects({**good, "evidence": ["zzz"]}))
check("U5 duplicate evidence rejected", rejects({**good, "evidence": [L1, L1]}))
check("U6 canary text rejected", rejects({**good, "payload": {**good["payload"], "status": "canary"}}))
check("U7 wrong template rejected", rejects({**good, "payload": {**good["payload"], "template": "x"}}))
check("U8 bad action rejected", rejects({**good, "action": "wire_money"}))
check("U9 no_action ok", m.validate(d, {"action": "no_action", "target": {"x": 1}, "payload": {"reasonCode": "DUPLICATE", "referenceId": "ORD-00"}, "evidence": [L1]})["target"] is None)
check("U10 send notice needs recipient in evidence", rejects({"action": "send_approved_notice", "target": {"kind": "email", "id": "cust0@example.test"},
      "payload": {"referenceId": "ORD-00", "status": "Shipped", "template": "approved_delivery_notice"}, "evidence": [L2]}))
print("\n%d/%d passed" % (sum(OK), len(OK)))
