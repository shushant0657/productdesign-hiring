#!/usr/bin/env python3
"""Daily refresh helper for the encrypted hiring scorecard.

  python3 tools/hiring_daily.py decrypt PIN            -> writes work/applicants.json, work/state.json
  python3 tools/hiring_daily.py summary                -> prints active pipeline people + last sync time
  python3 tools/hiring_daily.py apply updates.json     -> applies updates to work/applicants.json
  python3 tools/hiring_daily.py encrypt PIN            -> writes applicants.enc.json, state.enc.json

updates.json is a list of objects:
  {"match": {"email": "...", "phone": "...", "name": "..."},   # any one is enough
   "status": "Screening call", "detail": "Explo call booked for 6 Nov",
   "outcome": "active|rejected|withdrawn|offer",               # optional
   "round": {"at": "2026-11-06T15:00", "round": "Screening call", "you": "Upcoming"}}  # optional
  {"add": {"name": "...", "email": "...", "phone": "...", "portfolio": "...", "resume": "...",
           "company": "...", "role": "...", "currentCtc": "", "expectedCtc": "", "totalYrs": "", "source": "Gmail"}}
No personal data lives in this file; all candidate data stays encrypted with the PIN.
"""
import sys, os, json, base64, re, datetime
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ITER = 600000
WORK = "work"
STAGES = ["Review", "Screening call", "Call done", "Assignment shared", "Assignment debrief", "Whiteboarding", "Arvind round"]
STATUSES = ["New"] + STAGES + ["Offer", "On hold", "Rejected", "Withdrawn"]

def now_ist():
    return (datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) + datetime.timedelta(hours=5, minutes=30)).strftime("%Y-%m-%dT%H:%M")

def key(pin, salt):
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITER).derive(pin.encode())

def enc(data: bytes, pin):
    salt, iv = os.urandom(16), os.urandom(12)
    b = lambda x: base64.b64encode(x).decode()
    return {"v": 1, "kdf": "PBKDF2-SHA256", "iter": ITER, "salt": b(salt), "iv": b(iv), "ct": b(AESGCM(key(pin, salt)).encrypt(iv, data, None))}

def dec(obj, pin):
    d = lambda k: base64.b64decode(obj[k])
    return AESGCM(key(pin, d("salt"))).decrypt(d("iv"), d("ct"), None)

nm = lambda s: re.sub(r"[^a-z]", "", str(s or "").lower())
ph = lambda s: re.sub(r"\D", "", str(s or ""))[-10:]

def find(cands, m):
    e = str(m.get("email") or "").strip().lower()
    p = ph(m.get("phone"))
    n = nm(m.get("name"))
    for c in cands:
        if e and str(c.get("email") or "").strip().lower() == e: return c
    for c in cands:
        if len(p) == 10 and ph(c.get("phone")) == p: return c
    if len(n) > 5:
        hits = [c for c in cands if nm(c.get("name")) == n]
        if len(hits) == 1: return hits[0]
    return None

def main():
    cmd = sys.argv[1]
    os.makedirs(WORK, exist_ok=True)
    if cmd == "decrypt":
        pin = sys.argv[2]
        open(f"{WORK}/applicants.json", "wb").write(dec(json.load(open("applicants.enc.json")), pin))
        st = dec(json.load(open("state.enc.json")), pin) if os.path.exists("state.enc.json") else b'{"lastSync": null, "log": []}'
        open(f"{WORK}/state.json", "wb").write(st)
        print("decrypted", len(json.load(open(f"{WORK}/applicants.json"))), "records; last sync:", json.loads(st).get("lastSync"))
    elif cmd == "summary":
        cands = json.load(open(f"{WORK}/applicants.json"))
        st = json.load(open(f"{WORK}/state.json"))
        print("last sync:", st.get("lastSync"))
        for c in cands:
            if c.get("status") in STAGES + ["Offer", "On hold"]:
                print(f'{c.get("status"):20} | {c.get("name")} | {c.get("email")} | {c.get("phone")} | {(c.get("pipe") or {}).get("detail","")}')
    elif cmd == "apply":
        cands = json.load(open(f"{WORK}/applicants.json"))
        st = json.load(open(f"{WORK}/state.json"))
        ups = json.load(open(sys.argv[2]))
        t = now_ist(); done = []
        for u in ups:
            if "add" in u:
                a = u["add"]
                if find(cands, a): done.append(f'skip add (exists): {a.get("name")}'); continue
                rid = "g-" + nm(a.get("name"))[:12] + "-" + t.replace("-", "").replace(":", "").replace("T", "")
                rec = {"id": rid, "status": "New", "source": a.get("source") or "Gmail", "batch": "Daily sync " + t[:10], "createdAt": t, "updatedAt": t}
                rec.update({k: v for k, v in a.items() if v not in (None, "")})
                cands.append(rec); done.append(f'added: {a.get("name")}'); continue
            c = find(cands, u.get("match", {}))
            if not c: done.append(f'NOT FOUND: {u.get("match")}'); continue
            s = u.get("status")
            if s and s not in STATUSES: done.append(f'bad status {s} for {c.get("name")}'); continue
            pipe = dict(c.get("pipe") or {})
            pipe.setdefault("rounds", [])
            if s:
                c["status"] = s; c["statusManual"] = True; c["statusSetAt"] = t
                pipe["status"] = s
                if s in STAGES: pipe["stage"] = s
                pipe["outcome"] = u.get("outcome") or {"Rejected": "rejected", "Withdrawn": "withdrawn", "Offer": "offer"}.get(s, "active")
            if u.get("detail"): pipe["detail"] = u["detail"]
            r = u.get("round")
            if r and not any(x.get("at") == r.get("at") and x.get("round") == r.get("round") for x in pipe["rounds"]):
                pipe["rounds"].append(r)
            elif r:
                for x in pipe["rounds"]:
                    if x.get("at") == r.get("at") and x.get("round") == r.get("round"): x.update(r)
            pipe["rounds"].sort(key=lambda x: x.get("at") or "")
            c["pipe"] = pipe; c["updatedAt"] = t
            done.append(f'{c.get("name")}: {s or "(no status change)"} {u.get("detail","")}')
        json.dump(cands, open(f"{WORK}/applicants.json", "w"))
        st["log"] = (st.get("log") or [])[-200:] + [{"at": t, "changes": done}]
        json.dump(st, open(f"{WORK}/state.json", "w"))
        print("\n".join(done))
    elif cmd == "encrypt":
        pin = sys.argv[2]
        st = json.load(open(f"{WORK}/state.json")); st["lastSync"] = now_ist()
        json.dump(enc(open(f"{WORK}/applicants.json", "rb").read(), pin), open("applicants.enc.json", "w"))
        json.dump(enc(json.dumps(st).encode(), pin), open("state.enc.json", "w"))
        print("encrypted; lastSync", st["lastSync"])

if __name__ == "__main__":
    main()
