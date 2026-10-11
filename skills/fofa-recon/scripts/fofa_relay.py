#!/usr/bin/env python3
"""fafaapi.info 中转客户端：单线程 + 最小间隔 + 结果缓存。

用法:
  python3 scripts/fofa_relay.py 'domain="example.com"' --pages 2 --size 100 --interval 2.5
输出:
  runs/fofa-<slug>.jsonl   每行一个资产 {host,ip,port,title,domain,server,protocol,country,asn}
凭据:
  key 优先读环境变量 FOFA_KEY（ARTEX 系统配置→红队环境变量注入），未设置时用下方兜底值。
"""
import argparse, base64, hashlib, json, os, sys, time, urllib.error, urllib.parse, urllib.request

KEY = os.environ.get("FOFA_KEY", "").strip() or "86d6c2f1b8b2dffd43d49b3a986f85b9"
API = "https://fafaapi.info/fofaapi"
FIELDS = "host,ip,port,title,domain,server,protocol,country,asn"

def fetch(query, page, size, route="1", timeout=60):
    qs = urllib.parse.urlencode({
        "key": KEY,
        "queryStr": base64.b64encode(query.encode()).decode(),
        "fields": ",".join(FIELDS.split(",")),
        "page": page, "size": size, "route": route, "full": "false",
    })
    req = urllib.request.Request(API + "?" + qs, headers={"User-Agent": "Mozilla/5.0 redteam-recon"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "ignore")
        try:
            return e.code, json.loads(body)
        except Exception:
            return e.code, {"error": True, "errmsg": body[:300]}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("query")
    ap.add_argument("--pages", type=int, default=1)
    ap.add_argument("--size", type=int, default=100)
    ap.add_argument("--interval", type=float, default=3.5)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    slug = hashlib.md5(args.query.encode()).hexdigest()[:8]
    out = args.out or f"runs/fofa-{slug}.jsonl"
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    if os.path.exists(out) and os.path.getsize(out) > 0:
        print(f"[cache] {out}", file=sys.stderr); return 0
    seen, rows, last_ts = set(), [], 0.0
    for page in range(1, args.pages + 1):
        wait = args.interval - (time.time() - last_ts)
        if wait > 0: time.sleep(wait)
        last_ts = time.time()
        status, data = fetch(args.query, page, args.size)
        if status != 200 or data.get("error"):
            print(f"[stop] http={status} {data.get('errmsg') or data}", file=sys.stderr)
            break
        results = data.get("finalResults") or data.get("data") or []
        total = data.get("total")
        print(f"[page {page}] {len(results)} rows total={total} remain={data.get('newTodayRemaining')}", file=sys.stderr)
        for item in results:
            if isinstance(item, dict) and isinstance(item.get("fields"), dict):
                row = item["fields"]
            elif isinstance(item, list):
                row = dict(zip(FIELDS.split(","), item))
            else:
                row = item
            key = (row.get("host"), row.get("ip"), row.get("port"))
            if key in seen: continue
            seen.add(key); rows.append(row)
        if len(results) < args.size: break
    with open(out, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"[done] {len(rows)} rows -> {out}", file=sys.stderr)
    return 0

if __name__ == "__main__":
    sys.exit(main())
