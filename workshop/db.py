"""Shared DuckDB setup for every lab: raw views, the OCSF contract, mapper loading, fixtures."""

import json
import os
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
# WORKSHOP_DATA points everything at an alternate dataset (e.g. a larger benchmark build).
DATA = Path(os.environ.get("WORKSHOP_DATA", ROOT / "data"))
RAW = DATA / "raw"
FIXTURES = DATA / "fixtures"
CLOUDS = ("eks", "gke", "aks")

# Each cloud's envelope is unwrapped once so mappers start from one JSON audit event per row.
RAW_VIEWS = {
    "raw_eks": f"""
        SELECT owner AS aws_account, logGroup AS log_group, logStream AS log_stream,
               le.timestamp AS cw_timestamp_ms, json(le.message) AS event
        FROM (SELECT owner, logGroup, logStream, unnest(logEvents) AS le
              FROM read_json('{RAW}/eks/eks_audit.jsonl.gz', format='newline_delimited',
                             maximum_object_size=67108864))""",
    "raw_gke": f"""
        SELECT json AS entry
        FROM read_ndjson_objects('{RAW}/gke/gke_audit.jsonl.gz')""",
    "raw_aks": f"""
        SELECT r.time AS time, r.resourceId AS resource_id, r.category AS category,
               r.properties.pod AS apiserver_pod, json(r.properties.log) AS event
        FROM (SELECT unnest(records) AS r
              FROM read_json('{RAW}/aks/aks_audit.jsonl.gz', format='newline_delimited',
                             maximum_object_size=67108864))""",
}

# Cloud-agnostic helpers so mappers only express what differs per cloud.
MACROS = [
    """CREATE MACRO k8s_activity_id(verb) AS CASE
           WHEN verb = 'create' THEN 1
           WHEN verb IN ('get', 'list', 'watch') THEN 2
           WHEN verb IN ('update', 'patch') THEN 3
           WHEN verb IN ('delete', 'deletecollection') THEN 4
           ELSE 99 END""",
    """CREATE MACRO k8s_activity_name(id) AS
           CASE id WHEN 1 THEN 'Create' WHEN 2 THEN 'Read' WHEN 3 THEN 'Update' WHEN 4 THEN 'Delete' ELSE 'Other' END""",
    """CREATE MACRO k8s_user_type(name) AS CASE
           WHEN name LIKE 'system:serviceaccount:%' OR name LIKE '%.gserviceaccount.com'
                OR regexp_full_match(name, '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}') THEN 'ServiceAccount'
           WHEN name = 'system:anonymous' THEN 'Anonymous'
           WHEN name LIKE 'system:%' OR name LIKE 'eks:%' OR name = 'aksService' THEN 'System'
           ELSE 'User' END""",
    """CREATE MACRO k8s_user_type_id(name) AS
           CASE k8s_user_type(name) WHEN 'User' THEN 1 WHEN 'System' THEN 3 ELSE 99 END""",
    """CREATE MACRO http_status_id(code) AS CASE WHEN code IS NULL THEN 0 WHEN code < 400 THEN 1 ELSE 2 END""",
    """CREATE MACRO status_name(id) AS CASE id WHEN 1 THEN 'Success' WHEN 2 THEN 'Failure' ELSE 'Unknown' END""",
]

# Subset of OCSF 1.3 API Activity (class 6003) used throughout the workshop.
OCSF_API_ACTIVITY = {
    "class_uid": "INTEGER",
    "category_uid": "INTEGER",
    "activity_id": "INTEGER",
    "activity_name": "VARCHAR",
    "type_uid": "INTEGER",
    "time": "TIMESTAMPTZ",
    "status_id": "INTEGER",
    "status": "VARCHAR",
    "status_code": "VARCHAR",
    "metadata": "STRUCT(uid VARCHAR, version VARCHAR, log_name VARCHAR, original_time VARCHAR, "
                "product STRUCT(name VARCHAR, vendor_name VARCHAR))",
    "cloud": "STRUCT(provider VARCHAR, region VARCHAR, "
             "account STRUCT(uid VARCHAR, labels MAP(VARCHAR, VARCHAR)))",
    "actor": 'STRUCT("user" STRUCT(name VARCHAR, uid VARCHAR, email_addr VARCHAR, type VARCHAR, type_id INTEGER, '
             "groups STRUCT(name VARCHAR)[]), "
             "authorizations STRUCT(decision VARCHAR, policy STRUCT(name VARCHAR))[])",
    "api": 'STRUCT(operation VARCHAR, version VARCHAR, service STRUCT(name VARCHAR), "group" STRUCT(name VARCHAR), '
           "request STRUCT(uid VARCHAR, data JSON), response STRUCT(code INTEGER, message VARCHAR, data JSON))",
    "resources": "STRUCT(type VARCHAR, name VARCHAR, namespace VARCHAR)[]",
    "src_endpoint": "STRUCT(ip VARCHAR)",
    "http_request": "STRUCT(user_agent VARCHAR, url STRUCT(path VARCHAR))",
}


def mapper_dir():
    return Path(os.environ.get("LAB2_DIR", ROOT / "labs" / "lab2_ocsf"))


def connect(mappers=True, fixtures=True, mapper_path=None, database=":memory:"):
    """Workshop DB (in-memory by default) with raw, OCSF, and fixture views."""
    import duckdb

    con = duckdb.connect(str(database))
    initialize(con, mappers=mappers, fixtures=fixtures, mapper_path=mapper_path)
    return con


def initialize(con, mappers=True, fixtures=True, mapper_path=None):
    """Create or refresh workshop views on an existing connection."""
    for macro in MACROS:
        con.sql(macro.replace("CREATE MACRO", "CREATE OR REPLACE MACRO", 1))
    for name, sql in RAW_VIEWS.items():
        con.sql(f"CREATE OR REPLACE VIEW {name} AS {sql}")
    if mappers:
        load_mappers(con, mapper_path or mapper_dir())
    if fixtures:
        for csv in sorted(FIXTURES.glob("*.csv")):
            con.sql(f"CREATE OR REPLACE VIEW {csv.stem} AS SELECT * FROM read_csv('{csv}', header=true)")


def load_mappers(con, path):
    path = Path(path)
    for cloud in CLOUDS:
        body = (path / f"{cloud}.sql").read_text().strip().rstrip(";")
        con.sql(f"CREATE OR REPLACE VIEW ocsf_{cloud}_uncast AS {body}")
        casts = ", ".join(f'CAST("{c}" AS {t}) AS "{c}"' for c, t in OCSF_API_ACTIVITY.items())
        con.sql(f"CREATE OR REPLACE VIEW ocsf_{cloud} AS SELECT {casts} FROM ocsf_{cloud}_uncast")
    con.sql("CREATE OR REPLACE VIEW ocsf_api_activity AS " +
            " UNION ALL BY NAME ".join(f"SELECT * FROM ocsf_{c}" for c in CLOUDS))


def shape(value):
    """Nested key structure of a JSON-ish value, for comparing struct field names."""
    if isinstance(value, dict):
        return {k: shape(v) for k, v in value.items()}
    if isinstance(value, list):
        return [shape(value[0])] if value and isinstance(value[0], dict) else []
    return None


def field_shape(con, view):
    """Union of nested field names over a sample of rows (lists are often empty on a single row)."""
    merged = {}

    def merge(dst, src):
        # A JSON-typed column can be an object on one row and null/scalar on the next.
        for k, v in src.items():
            if isinstance(v, dict):
                if not isinstance(dst.get(k), dict):
                    dst[k] = {}
                merge(dst[k], v)
            elif isinstance(v, list) and v:
                if not isinstance(dst.get(k), list) or not dst[k]:
                    dst[k] = [{}]
                merge(dst[k][0], v[0])
            else:
                dst.setdefault(k, None)

    for (row,) in con.sql(f"SELECT to_json(t) FROM (SELECT * FROM {view} USING SAMPLE 300 ROWS) t").fetchall():
        merge(merged, shape(json.loads(row)))
    return merged


def _parse_type(s, i=0):
    """Parse a DuckDB type string into nested field names; returns (shape, next_index)."""
    if s.startswith("STRUCT(", i):
        i += len("STRUCT(")
        fields = {}
        while s[i] != ")":
            if s[i] == '"':
                end = s.index('"', i + 1)
                name, i = s[i + 1:end], end + 2
            else:
                end = s.index(" ", i)
                name, i = s[i:end], end + 1
            fields[name], i = _parse_type(s, i)
            if s.startswith(", ", i):
                i += 2
        i += 1
        if s.startswith("[]", i):
            return [fields], i + 2
        return fields, i
    depth = 0
    while i < len(s) and (depth or s[i] not in ",)"):
        depth += {"(": 1, ")": -1}.get(s[i], 0)
        i += 1
    return None, i


def contract_shape():
    return {c: _parse_type(t)[0] for c, t in OCSF_API_ACTIVITY.items()}


def shape_diff(expected, actual, path=""):
    """Field-name mismatches between contract and mapper output; unsampled (empty) lists are skipped."""
    problems = []
    if isinstance(expected, list):
        if isinstance(actual, list) and actual:
            problems += shape_diff(expected[0], actual[0], path + "[]")
        return problems
    if not isinstance(expected, dict) or actual is None:
        return problems
    if not isinstance(actual, dict):
        return [f"{path or '<root>'}: expected a struct"]
    for k in expected.keys() - actual.keys():
        problems.append(f"missing field {path}{'.' if path else ''}{k}")
    for k in actual.keys() - expected.keys():
        problems.append(f"unexpected field {path}{'.' if path else ''}{k}")
    for k in expected.keys() & actual.keys():
        problems += shape_diff(expected[k], actual[k], f"{path}{'.' if path else ''}{k}")
    return problems
