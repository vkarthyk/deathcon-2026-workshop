"""Build data/expected/lab2_golden.csv from the solution mappers.

Rows: every attack event, every FP-trap lookalike, plus a deterministic ~0.5% sample of the rest.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from workshop.db import ROOT, CLOUDS, connect  # noqa: E402
from workshop.grading import select_graded  # noqa: E402

con = connect(fixtures=False, mapper_path=ROOT / "solutions" / "lab2_ocsf")
con.sql(f"CREATE VIEW gt AS SELECT * FROM read_csv('{ROOT}/data/raw/ground_truth.csv')")
parts = []
for cloud in CLOUDS:
    parts.append(f"""
        SELECT '{cloud}' AS cloud, g.* FROM ({select_graded(f'ocsf_{cloud}')}) g
        JOIN ocsf_{cloud} o ON o.metadata.uid = g.uid
        WHERE g.uid IN (SELECT auditID FROM gt WHERE cloud = '{cloud}')
           OR (o.api.operation = 'create' AND o.resources[1].type IN ('pods', 'pods/exec'))
           OR o.resources[1].type = 'clusterrolebindings'
           OR o.actor.user.type = 'Anonymous'
           OR hash(g.uid) % 200 = 0""")
out = ROOT / "data" / "expected" / "lab2_golden.csv"
con.sql(" UNION ALL ".join(parts) + " ORDER BY cloud, uid").write_csv(str(out))
print(con.sql(f"SELECT cloud, count(*) FROM read_csv('{out}') GROUP BY 1 ORDER BY 1").fetchall())
