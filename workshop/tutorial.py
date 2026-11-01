"""Small, stateless helpers for the runnable tutorial notebooks."""

from workshop.db import RAW, ROOT, connect


def open_workshop(raw_only=False, mappings="solutions"):
    """Use an independent in-memory connection, avoiding the UI database's file lock."""
    if mappings not in ("solutions", "participant"):
        raise ValueError("mappings must be 'solutions' or 'participant'")
    path = ROOT / ("solutions" if mappings == "solutions" else "labs") / "lab2_ocsf"
    con = connect(mappers=not raw_only, mapper_path=path)
    # Evaluation only: detection rules must never select their IDs from this view.
    truth_path = str(RAW / "ground_truth.csv").replace("'", "''")
    con.execute(f"CREATE VIEW evaluation_truth AS SELECT * FROM read_csv('{truth_path}', all_varchar=true)")
    print("Raw views and enrichment fixtures ready." if raw_only else f"OCSF views ready ({mappings} mappings).")
    return con


def q(con, sql, limit=20):
    """Preview rows without hiding the full query's result set from the evaluator."""
    return con.sql(sql).limit(limit).df()


def compare(con, candidate, reference):
    """Exact event-ID comparison against a supplied reference (not maliciousness)."""
    def ids(sql):
        relation = con.sql(sql)
        if "event_id" not in relation.columns:
            raise ValueError("Queries must return an event_id column")
        return {row[0] for row in relation.project("event_id").fetchall()}

    actual, expected = ids(candidate), ids(reference)
    result = {"match": actual == expected, "candidate_hits": len(actual),
              "reference_hits": len(expected), "missing": len(expected - actual),
              "extra": len(actual - expected)}
    print(result)
    return result


def evaluate(con, sql):
    """Label rule hits for discussion; ground truth is never a detection input."""
    sql = sql.strip().rstrip(";")
    return con.sql(f"""
        SELECT h.*, (t.auditID IS NOT NULL) AS is_attack,
               t.step AS attack_step, t.mitre_technique
        FROM ({sql}) h
        LEFT JOIN evaluation_truth t ON t.auditID = h.event_id
        ORDER BY h.event_id
    """).df()
