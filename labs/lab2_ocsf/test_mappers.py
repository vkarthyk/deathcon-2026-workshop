"""Lab 2 autograder.

    python3.11 -m pytest labs/lab2_ocsf -q                 # grade your mappers
    LAB2_DIR=solutions/lab2_ocsf python3.11 -m pytest labs/lab2_ocsf -q   # grade the reference
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from workshop.db import CLOUDS, ROOT, connect, contract_shape, field_shape, shape_diff  # noqa: E402
from workshop.grading import CROSS_CLOUD_FIELDS, GRADED_FIELDS, select_graded  # noqa: E402

GOLDEN = ROOT / "data" / "expected" / "lab2_golden.csv"


@pytest.fixture(scope="module")
def con():
    c = connect(fixtures=False)
    c.sql(f"CREATE VIEW golden AS SELECT * FROM read_csv('{GOLDEN}', all_varchar=true)")
    c.sql(f"CREATE VIEW gt AS SELECT * FROM read_csv('{ROOT}/data/raw/ground_truth.csv', all_varchar=true)")
    for cloud in CLOUDS:
        c.sql(f"CREATE TEMP TABLE graded_{cloud} AS {select_graded(f'ocsf_{cloud}')}")
    return c


@pytest.mark.parametrize("cloud", CLOUDS)
def test_one_row_per_raw_event(con, cloud):
    raw = con.sql(f"SELECT count(*) FROM raw_{cloud}").fetchone()[0]
    out = con.sql(f"SELECT count(*) FROM ocsf_{cloud}").fetchone()[0]
    assert out == raw, f"{cloud}: mapper produced {out} rows from {raw} raw events (dropped or duplicated rows?)"


@pytest.mark.parametrize("cloud", CLOUDS)
def test_matches_ocsf_contract(con, cloud):
    problems = shape_diff(contract_shape(), field_shape(con, f"ocsf_{cloud}_uncast"))
    assert not problems, f"{cloud}: output does not match the OCSF contract:\n  " + "\n  ".join(problems)


@pytest.mark.parametrize("field", GRADED_FIELDS)
@pytest.mark.parametrize("cloud", CLOUDS)
def test_field_matches_reference(con, cloud, field):
    rows = con.sql(f"""
        SELECT g.uid, g."{field}" AS expected, m."{field}" AS actual
        FROM golden g LEFT JOIN graded_{cloud} m ON m.uid = g.uid
        WHERE g.cloud = '{cloud}' AND g."{field}" IS DISTINCT FROM m."{field}"
    """).fetchall()
    total = con.sql(f"SELECT count(*) FROM golden WHERE cloud = '{cloud}'").fetchone()[0]
    if rows:
        examples = "\n".join(f"    auditID={u}  expected={e!r}  got={a!r}" for u, e, a in rows[:3])
        pytest.fail(f"{cloud} {field}: {len(rows)}/{total} graded events differ, e.g.\n{examples}")


def test_attack_chain_is_identical_across_clouds(con):
    """The payoff: one detection works everywhere only if these fields agree for every attack step."""
    union = " UNION ALL ".join(f"SELECT '{c}' AS cloud, * FROM graded_{c}" for c in CLOUDS)
    diffs = []
    for field in CROSS_CLOUD_FIELDS:
        rows = con.sql(f"""
            WITH steps AS (
                SELECT gt.step, row_number() OVER (PARTITION BY gt.cloud, gt.step ORDER BY a.time) AS seq,
                       a.cloud, a."{field}" AS v
                FROM ({union}) a JOIN gt ON gt.auditID = a.uid AND gt.cloud = a.cloud)
            SELECT step, seq, string_agg(cloud || '=' || coalesce(v, 'NULL'), ', ' ORDER BY cloud)
            FROM steps GROUP BY step, seq
            HAVING count(DISTINCT coalesce(v, 'NULL')) > 1 OR count(*) < {len(CLOUDS)}
            ORDER BY step::INT, seq""").fetchall()
        diffs += [f"  step {s}.{q} {field}: {vals}" for s, q, vals in rows]
    assert not diffs, "attack steps normalize differently across clouds:\n" + "\n".join(diffs[:15])
