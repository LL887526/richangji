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
DATA_FILE = Path(os.environ.get("BAND_DATA_FILE", "data/band-466d8dc5ea4412240954eb35.json"))


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


def fetch_nights(creds: dict, days: int = 9) -> tuple[dict, dict]:
    """拉最近 N 天睡眠，按起床日(UTC+8)归档，同日多段取时长最长的一段。"""
    end = int(time.time())
    start = end - days * 86400
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
    nights: dict[str, dict] = {}
    latest = None
    for item in (body.get("result") or {}).get("data_list") or []:
        v = item.get("value", "{}")
        if isinstance(v, str):
            try:
                v = json.loads(v)
            except json.JSONDecodeError:
                continue
        minutes = int(v.get("duration") or 0)
        if minutes <= 0:
            continue
        end_ts = int(v.get("device_wake_up_time") or v.get("end_time") or item.get("time") or 0)
        bed_ts = int(v.get("bedtime") or v.get("device_bedtime") or 0)
        if not end_ts:
            continue
        day = datetime.fromtimestamp(end_ts, TZ8).strftime("%Y-%m-%d")
        span = round((end_ts - bed_ts) / 60) if end_ts > bed_ts else minutes

        def _h(key):
            return round(int(v.get(key) or 0) / 60 * 10) / 10

        rec = {
            "h": round(minutes / 60 * 10) / 10,
            "hd": round(span / 60 * 10) / 10,
            "end": end_ts,
            "bed": bed_ts,
            "deep": _h("sleep_deep_duration"),
            "light": _h("sleep_light_duration"),
            "rem": _h("sleep_rem_duration"),
            "awake": _h("sleep_awake_duration"),
            "awakeN": int(v.get("awake_count") or 0),
            "hr": int(v.get("avg_hr") or 0),
            "spo2": int(v.get("avg_spo2") or 0),
            "spo2Min": int(v.get("min_spo2") or 0),
            "breath": int(v.get("breath_quality") or 0),
        }
        rec["eff"] = round(minutes / span * 100) if span > 0 else 0
        # 同日取最长一段（排除零星小睡覆盖主睡眠）
        if day not in nights or rec["h"] > nights[day]["h"]:
            nights[day] = rec
        if latest is None or end_ts > latest[0]:
            latest = (end_ts, day, rec)
    if latest is None:
        raise RuntimeError("no sleep data in window")
    return nights, {"d": latest[1], **latest[2]}


def fetch_series(creds: dict, key: str, days: int = 9) -> list:
    """拉某类时序数据（steps / heart_rate / stress / spo2），返回 [(ts, dict)] 升序。"""
    end = int(time.time())
    start = end - days * 86400
    form = build_form(SLEEP_PATH, {"start_time": start, "end_time": end, "key": key}, creds["ssecurity"])
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
        raise RuntimeError(f"{key} code {body.get('code')}")
    rows = []
    for item in (body.get("result") or {}).get("data_list") or []:
        v = item.get("value", "{}")
        if isinstance(v, str):
            try:
                v = json.loads(v)
            except json.JSONDecodeError:
                continue
        if not isinstance(v, dict):
            continue
        ts = int(item.get("time") or v.get("time") or 0)
        if ts > 10 ** 12:          # 毫秒时间戳
            ts //= 1000
        if ts <= 0:
            continue
        rows.append((ts, v))
    rows.sort(key=lambda x: x[0])
    return rows


def collect_days(creds: dict, days: int = 9) -> dict:
    """把四类时序按 UTC+8 自然日聚合。任一类失败只跳过该类，不影响睡眠主链路。"""
    out: dict = {}

    def slot(ts):
        day = datetime.fromtimestamp(ts, TZ8).strftime("%Y-%m-%d")
        return out.setdefault(day, {"steps": 0, "dist": 0.0, "kcal": 0,
                                    "_hr": [], "_stress": [], "_spo2": []})

    try:
        for ts, v in fetch_series(creds, "steps", days):
            s = slot(ts)
            s["steps"] += int(v.get("steps") or 0)
            s["dist"] += float(v.get("distance") or 0)
            s["kcal"] += int(v.get("calories") or 0)
    except Exception as e:
        print("SERIES_SKIP steps", repr(e)[:90])

    try:
        for ts, v in fetch_series(creds, "heart_rate", days):
            bpm = int(v.get("bpm") or 0)
            if 30 <= bpm <= 220:
                slot(ts)["_hr"].append(bpm)
    except Exception as e:
        print("SERIES_SKIP heart_rate", repr(e)[:90])

    try:
        for ts, v in fetch_series(creds, "stress", days):
            val = int(v.get("stress") or 0)
            if 1 <= val <= 100:
                slot(ts)["_stress"].append(val)
    except Exception as e:
        print("SERIES_SKIP stress", repr(e)[:90])

    try:
        for ts, v in fetch_series(creds, "spo2", days):
            val = int(v.get("spo2") or 0)
            if 70 <= val <= 100:
                slot(ts)["_spo2"].append(val)
    except Exception as e:
        print("SERIES_SKIP spo2", repr(e)[:90])

    for s in out.values():
        hr, st, sp = s.pop("_hr"), s.pop("_stress"), s.pop("_spo2")
        dist = s["dist"]
        s["dist"] = round(dist / 1000, 1) if dist > 300 else round(dist, 1)
        s["hr"] = round(sum(hr) / len(hr)) if hr else 0
        s["hrMin"] = min(hr) if hr else 0
        s["hrMax"] = max(hr) if hr else 0
        s["stress"] = round(sum(st) / len(st)) if st else 0
        s["stressMax"] = max(st) if st else 0
        s["spo2"] = round(sum(sp) / len(sp)) if sp else 0
        s["spo2Min"] = min(sp) if sp else 0
    return out


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
        nights, latest = fetch_nights(creds)
    except RuntimeError as e:
        if str(e) == "TOKEN_EXPIRED" and creds.get("passToken"):
            creds = refresh_by_passtoken(creds)
            nights, latest = fetch_nights(creds)
        else:
            raise
    save_creds(creds)

    days_map = collect_days(creds)

    top = {k: v for k, v in latest.items() if k != "end"}
    out = {
        **top,
        "nights": {k: {kk: vv for kk, vv in v.items() if kk != "end"}
                   for k, v in sorted(nights.items())},
        "days": days_map,
        "t": int(time.time()),
    }
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    DATA_FILE.write_text(json.dumps(out, separators=(",", ":"), ensure_ascii=False), encoding="utf-8")
    print("BAND_SYNC_OK", json.dumps({"latest": out["d"], "nights": len(out["nights"]),
                                      "days": len(days_map)}))


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
