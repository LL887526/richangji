# -*- coding: utf-8 -*-
"""第二轮探测：找「情绪」对应的真实数据项，并取样例结构。

同一个端点 /app/v1/data/get_fitness_data_by_time，只改 payload 里的 key。
结果写 data/_band_probe2.json，band_action 里以该文件存在为「已探过」标记。
"""
import json
import os
import time

import band_action as B

CANDIDATES = [
    # 情绪 / 心理
    "emotion", "emotions", "mood", "mood_score", "emotion_score", "emotion_type",
    "emotion_record", "emotion_state", "emotion_tag", "mood_tag", "emotion_monitor",
    "mental", "mental_health", "mental_pressure", "psychological", "affect", "feeling", "wellbeing",
    # 压力变体
    "stress_level", "pressure_score", "relax", "relaxation", "stress_record",
    # 其他可能有用的
    "energy", "fatigue", "tired", "body_battery", "hrv",
    "blood_pressure", "respiratory_rate", "breath", "temperature_body", "body_temperature",
    "sleep_stage", "sleep_stages", "sleep_detail",
    "workout_record", "sport_record", "exercise_record", "training",
    "vo2max", "fitness_age", "run_record", "walk_record",
    "stand_count", "sedentary_time", "activity_minutes", "move_minutes",
]

OUT = os.environ.get("BAND_PROBE_OUT", "_band_probe2.json")


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
    fields, sample = [], None
    if dl:
        v = dl[0].get("value")
        if isinstance(v, str):
            try:
                v = json.loads(v)
            except Exception:
                v = {}
        if isinstance(v, dict):
            fields = sorted(v.keys())[:30]
        elif isinstance(v, list) and v and isinstance(v[0], dict):
            fields = sorted(v[0].keys())[:30]
        sample = json.dumps(dl[0].get("value"), ensure_ascii=False)[:260]
    return {"code": body.get("code"), "n": len(dl), "fields": fields, "sample": sample}


def main():
    creds = B.load_creds()
    out = {}
    for key in CANDIDATES:
        try:
            res = probe(creds, key)
        except Exception as e:
            res = {"exc": str(e)[:80]}
        out[key] = res
        print("PROBE2", key, json.dumps(res, ensure_ascii=False))
        time.sleep(0.3)
    (B.DATA_FILE.parent / OUT).write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
    print("PROBE2_DONE", len(out), "hits", sum(1 for v in out.values() if v.get("n")))


if __name__ == "__main__":
    main()
