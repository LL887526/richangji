# -*- coding: utf-8 -*-
"""GitHub Actions 内运行：解密凭据 → 刷新 → 拉昨晚睡眠 → 写数据文件 + 回写密文状态。
仓库内只存在密文；明文凭据仅存活于 Secrets 与本次运行内存。
"""
import base64
import hashlib
import json
import os
import struct
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote

import requests

LOGIN_URL = "https://account.xiaomi.com/pass/serviceLogin"
HEALTH_API_BASE = "https://hlth.io.mi.com"
SLEEP_PATH = "/app/v1/data/get_fitness_data_by_time"
LOGIN_UA = ("Dalvik/2.1.0 (Linux; U; Android 12; V2284A Build/ab8c0d1.1) "
            "APP/mi.health APPV/353001 MK/VjIyODRB SDKV/5.3.0.release.68 "
            "CPN/com.mi.health PassportSDK/")
DATA_UA = "Android-12-3.53.1-vivo-V2284A"
SID = "miothealth"
TZ8 = timezone(timedelta(hours=8))

STATE_ENC = Path("band-state.enc")
DATA_FILE = Path(os.environ.get("BAND_DATA_FILE", "data/band-data.json"))


def parse_mi(text: str) -> dict:
    body = text[11:] if text.startswith("&&&START&&&") else text
    return json.loads(body)


# ---------- RC4 drop-1024 ----------
def rc4(key: bytes, data: bytes) -> bytes:
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    out = bytearray()
    i = j = 0
    for _ in range(1024):
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out.append(b ^ s[(s[i] + s[j]) & 0xFF])
    return bytes(out)


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


def b64d(s: str) -> bytes:
    return base64.b64decode(s)


def sha1_b64(msg: str) -> str:
    return b64e(hashlib.sha1(msg.encode()).digest())


def build_form(path: str, payload: dict, ssecurity: str) -> dict:
    data = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    nonce = os.urandom(8) + struct.pack(">I", int(time.time() // 60))
    snonce = hashlib.sha256(b64d(ssecurity) + nonce).digest()
    snonce_b64 = b64e(snonce)
    rc4_hash = sha1_b64(f"POST&{path}&data={data}&{snonce_b64}")
    enc_data = b64e(rc4(snonce, data.encode()))
    enc_hash = b64e(rc4(snonce, rc4_hash.encode()))
    signature = sha1_b64(f"POST&{path}&data={enc_data}&rc4_hash__={enc_hash}&{snonce_b64}")
    return {
        "data": enc_data,
        "rc4_hash__": enc_hash,
        "signature": signature,
        "_nonce": b64e(nonce),
    }


def decrypt_result(ssecurity: str, nonce_b64: str, cipher_b64: str):
    snonce = hashlib.sha256(b64d(ssecurity) + b64d(nonce_b64)).digest()
    return json.loads(rc4(snonce, b64d(cipher_b64)).decode())


# ---------- 凭据 ----------
def refresh_by_passtoken(creds: dict) -> dict:
    http = requests.Session()
    http.headers.update({"User-Agent": LOGIN_UA})
    device_id = "an_" + hashlib.md5(creds["userId"].encode()).hexdigest()
    for name, value in (("passToken", creds["passToken"]),
                        ("deviceId", device_id),
                        ("userId", creds["userId"])):
        http.cookies.set(name, value, domain="xiaomi.com")
        http.cookies.set(name, value, domain="mi.com")
    resp = http.get(LOGIN_URL, params={"_json": "true", "sid": SID}, timeout=30)
    data = parse_mi(resp.text)
    if not data.get("ssecurity"):
        raise RuntimeError(f"passToken 换取失败: {sorted(data.keys())}")
    new = dict(creds)
    new["ssecurity"] = data["ssecurity"]
    new["cUserId"] = str(data.get("cUserId") or creds.get("cUserId") or creds["userId"])
    if data.get("passToken"):
        new["passToken"] = data["passToken"]
    if data.get("location"):
        nonce_val = data.get("nonce", "")
        sign = quote(b64e(hashlib.sha1(f"nonce={nonce_val}&{data['ssecurity']}".encode()).digest()))
        r2 = http.get(data["location"] + "&clientSign=" + sign, timeout=30, allow_redirects=False)
        for c in r2.headers.get("Set-Cookie", "").split(","):
            if "serviceToken=" in c:
                new["serviceToken"] = c.split("serviceToken=")[1].split(";")[0]
                break
    if not new.get("serviceToken"):
        raise RuntimeError("刷新后无 serviceToken")
    return new


def fetch_sleep(creds: dict) -> dict:
    end = int(time.time())
    start = end - 40 * 3600
    form = build_form(SLEEP_PATH, {"start_time": start, "end_time": end, "key": "sleep"}, creds["ssecurity"])
    resp = requests.post(
        HEALTH_API_BASE + SLEEP_PATH,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": DATA_UA,
            "Cookie": f"cUserId={creds['cUserId']}; serviceToken={creds['serviceToken']}",
        },
        data=form, timeout=30)
    if resp.status_code in (401, 403):
        raise RuntimeError("TOKEN_EXPIRED")
    resp.raise_for_status()
    body = decrypt_result(creds["ssecurity"], form["_nonce"], resp.text.strip())
    if body.get("code") != 0:
        raise RuntimeError(f"api code {body.get('code')}: {body.get('message', '')}")
    best = None
    for item in (body.get("result") or {}).get("data_list") or []:
        v = item.get("value", "{}")
        if isinstance(v, str):
            try:
                v = json.loads(v)
            except json.JSONDecodeError:
                continue
        et = int(v.get("device_wake_up_time") or v.get("end_time") or item.get("time") or 0)
        if best is None or et > best[0]:
            best = (et, v)
    if best is None:
        raise RuntimeError("no sleep data in window")
    return best[1]


# ---------- 加密状态 ----------
def _aesgcm():
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    return AESGCM(key32())


def key32() -> bytes:
    return hashlib.sha256(os.environ["BAND_KEY"].encode()).digest()


def load_creds() -> dict:
    if STATE_ENC.exists():
        box = json.loads(STATE_ENC.read_text())
        plain = _aesgcm().decrypt(b64d(box["n"]), b64d(box["c"]), None)
        return json.loads(plain)
    return json.loads(os.environ["BAND_CREDS"])


def save_creds(creds: dict) -> None:
    nonce = os.urandom(12)
    ct = _aesgcm().encrypt(nonce, json.dumps(creds).encode(), None)
    STATE_ENC.write_text(json.dumps({"n": b64e(nonce), "c": b64e(ct)}))


def main() -> None:
    creds = load_creds()
    try:
        value = fetch_sleep(creds)
    except RuntimeError as e:
        if str(e) == "TOKEN_EXPIRED" and creds.get("passToken"):
            creds = refresh_by_passtoken(creds)
            value = fetch_sleep(creds)
        else:
            raise
    save_creds(creds)

    minutes = int(value.get("duration") or 0)
    end_ts = int(value.get("device_wake_up_time") or value.get("end_time") or 0)
    bed_ts = int(value.get("bedtime") or value.get("device_bedtime") or 0)
    span = round((end_ts - bed_ts) / 60) if end_ts > bed_ts else minutes
    out = {
        "h": round(minutes / 60 * 10) / 10,
        "hd": round(span / 60 * 10) / 10,
        "d": datetime.fromtimestamp(end_ts, TZ8).strftime("%Y-%m-%d"),
        "t": int(time.time()),
    }
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    DATA_FILE.write_text(json.dumps(out, separators=(",", ":")), encoding="utf-8")
    print("BAND_SYNC_OK", json.dumps(out))


if __name__ == "__main__":
    try:
        main()
    except Exception as e:  # 失败也要写状态文件，工作台据此提示
        DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
        msg = str(e)
        err = "need_relogin" if ("passToken" in msg or "TOKEN_EXPIRED" in msg or "换取" in msg) else "sync_error"
        DATA_FILE.write_text(json.dumps({"err": err, "t": int(time.time())}, separators=(",", ":")))
        print("BAND_SYNC_FAIL", msg)
        raise
