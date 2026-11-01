"""Lab 1 helpers: raw-log views, sample events, and a grader for each (rule, cloud) query."""

import csv
import json
import sys

from workshop.db import RAW, ROOT, connect

sys.path.insert(0, str(ROOT))
from solutions.lab1_raw.rules import RULES  # noqa: E402

CLOUDS = ("eks", "gke", "aks")
_con = None
_results = {}


def setup():
    global _con
    _con = connect(mappers=False, fixtures=False)
    counts = {c: _con.sql(f"SELECT count(*) FROM raw_{c}").fetchone()[0] for c in CLOUDS}
    print("Raw views ready:", ", ".join(f"raw_{c} ({n:,} events)" for c, n in counts.items()))
    return _con


def q(sql, limit=20):
    """Run SQL and return a DataFrame (first `limit` rows)."""
    return _con.sql(sql).limit(limit).df()


def sample(cloud, width=1600):
    """Pretty-print one raw record so you can see the shape each cloud delivers."""
    col = "entry" if cloud == "gke" else "event"
    extra = {"eks": "aws_account, log_group,", "aks": "time, resource_id, category,", "gke": ""}[cloud]
    row = _con.sql(f"""SELECT {extra} {col} FROM raw_{cloud}
                       WHERE {col}::VARCHAR LIKE '%"pods"%' OR {col}::VARCHAR LIKE '%pods.create%' LIMIT 1""")
    names, values = row.columns, row.fetchone()
    for name, value in zip(names, values):
        if name in ("event", "entry"):
            text = json.dumps(json.loads(value), indent=1)
            print(f"{name}:\n{text[:width]}{' ...' if len(text) > width else ''}")
        else:
            print(f"{name}: {value}")


def _truth():
    with open(RAW / "ground_truth.csv") as f:
        return {r["auditID"] for r in csv.DictReader(f)}


def check(rule, cloud, sql):
    """Grade one query: must return an event_id column with exactly the reference hits."""
    ref_sql = RULES[rule].get(cloud)
    if ref_sql is None:
        print(f"{rule}/{cloud}: no reference answer - see the notes above this cell.")
        return None
    # DuckDB relations are lazy: errors surface on fetch, so execution stays inside the try.
    try:
        columns = _con.sql(sql).columns
        if "event_id" not in columns:
            print(f"❌ {rule}/{cloud}: return a column named event_id (got {columns})")
            _results[(rule, cloud)] = False
            return False
        got = {r[0] for r in _con.sql(f"SELECT event_id FROM ({sql})").fetchall()}
    except Exception as e:
        print(f"❌ {rule}/{cloud}: query failed - {type(e).__name__}: {str(e).splitlines()[0][:200]}")
        if "->>" in sql or "->" in sql:
            print("   hint: in DuckDB `->>` binds looser than AND / = ; wrap each one in parentheses "
                  "or use json_extract_string(col, '$.path').")
        _results[(rule, cloud)] = False
        return False
    want = {r[0] for r in _con.sql(f"SELECT event_id FROM ({ref_sql})").fetchall()}
    attack = want & _truth()
    caught = got & attack
    ok = got == want
    _results[(rule, cloud)] = ok
    mark = "✅" if ok else "❌"
    print(f"{mark} {rule}/{cloud}: {len(got)} hits (expected {len(want)}); "
          f"attack events caught {len(caught)}/{len(attack)}")
    if not ok:
        if want - got:
            print(f"   missing {len(want - got)} expected hit(s) - is a filter too strict, or a field path wrong?")
        if got - want:
            print(f"   {len(got - want)} extra hit(s) - is a filter missing?")
    elif len(want) > len(attack):
        print(f"   {len(want) - len(attack)} of these are benign lookalikes. That's expected in Lab 1; "
              f"Lab 4 clears them with context.")
    return ok


def scorecard():
    """✅ passed, ❌ failed, · not attempted, n/a not possible on that cloud."""
    width = max(len(r) for r in RULES)
    print("rule".ljust(width) + "".join(c.rjust(6) for c in CLOUDS))
    for rule, by_cloud in RULES.items():
        marks = []
        for c in CLOUDS:
            if c not in by_cloud:
                marks.append("n/a")
            else:
                marks.append({True: "✅", False: "❌"}.get(_results.get((rule, c)), "·"))
        print(rule.ljust(width) + "".join(m.rjust(5) for m in marks))
