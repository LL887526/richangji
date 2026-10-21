# -*- coding: utf-8 -*-
"""探手环云端接口支持哪些数据项。

同一个端点 /app/v1/data/get_fitness_data_by_time，只改 payload 里的 key。
逐个 key 请求，打印 code / 条数 / 字段名，用来确定能拉哪些指标。
"""
import json
import time

import band_action as B

CANDIDATES = [
    "sleep",
    "steps", "step", "walk", "run",
    "heart_rate", "heartrate", "hr",
    "stress", "pressure",
    "emotion", "mood", "emotion_record",
    "spo2", "blood_oxygen", "oxygen",
    "weight", "body_fat",
    "calories", "calorie", "distance",
    "stand", "stand_hour", "sedentary",
    "activity", "activity_intensity",
    "pai", "vitality", "sleep_quality",
    "workout", "sport", "exercise",
    "skin_temperature", "temperature",
]


def probe(creds, key, days=3):
    end = int(time.time())
    start = end - days * 86400
    form = B.build_form(B.SLEEP_PATH, {"start_time": start, "end_time": end, "key": key}, creds["ssecurity"])
    r = B.requests.post(
        B.HEALTH_API_BASE + B.SLEEP_PATH,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": B.DATA_UA,
            "Cookie": "cUserId={}; serviceToken={}".format(creds["cUserId"], creds["serviceToken"]),
        },
        data=form, timeout=30)
    if r.status_code != 200:
        return {"http": r.status_code}
    try:
        body = B.decrypt_result(creds["ssecurity"], form["_nonce"], r.text.strip())
    except Exception as e:
        return {"decode_err": str(e)[:80]}
    dl = (body.get("result") or {}).get("data_list") or []
    fields = []
    if dl:
        v = dl[0].get("value")
        if isinstance(v, str):
            try:
                v = json.loads(v)
            except Exception:
                v = {}
        if isinstance(v, dict):
            fields = sorted(v.keys())[:26]
        elif isinstance(v, list) and v and isinstance(v[0], dict):
            fields = sorted(v[0].keys())[:26]
    return {"code": body.get("code"), "msg": (body.get("message") or "")[:60], "n": len(dl), "fields": fields}


def main():
    creds = B.load_creds()
    out = {}
    for key in CANDIDATES:
        try:
            res = probe(creds, key)
        except Exception as e:
            res = {"exc": str(e)[:80]}
        out[key] = res
        print("PROBE", key, json.dumps(res, ensure_ascii=False))
        time.sleep(0.35)
    if B.DATA_FILE.parent.exists():
        (B.DATA_FILE.parent / "_band_probe.json").write_text(
            json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
    print("PROBE_DONE", len(out))


if __name__ == "__main__":
    main()
