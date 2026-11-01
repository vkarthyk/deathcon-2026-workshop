"""Tool sets for the Lab 5 agent: the same evidence, exposed three ways.

Every mode sees identical information (raw cloud logs + the Lab 4 fixtures); only the shape differs:
  raw       - one SQL tool over the logs exactly as each cloud delivers them, plus the fixture tables
  ocsf      - purpose-built tools over the OCSF layer, separate lookup tools for context
  enriched  - one OCSF table with all context already joined onto every event; no lookups needed
"""

import copy
import json
import re
import threading
import time
from pathlib import Path

from workshop.db import FIXTURES, ROOT, connect

MAX_ROWS = 50
MAX_CHARS = 12_000
QUERY_TIMEOUT_S = 20


# Lab 4's joins, done once up front: identity, service account, IP reputation, asset and workload context.
ENRICHED_VIEW = """
CREATE VIEW ocsf_enriched AS
WITH base AS (
    SELECT o.*, regexp_extract(o.http_request.user_agent, '\\((darwin|linux|windows)/', 1) AS ua_os,
           o.api.request.data AS req
    FROM ocsf_api_activity o)
SELECT b.* EXCLUDE (ua_os, req, cloud),
    struct_pack(provider := b.cloud.provider, region := coalesce(b.cloud.region, c.region),
                account := b.cloud.account) AS cloud,
    struct_pack(
        actor := struct_pack(
            person_id := i.person_id, full_name := i.display_name, department := i.department, title := i.title,
            out_of_office := nullif(i.out_of_office, ''), usual_client_os := i.usual_client_os,
            client_os_mismatch := CASE WHEN i.usual_client_os IS NOT NULL AND b.ua_os <> ''
                                       THEN b.ua_os <> i.usual_client_os END,
            principal_kind := coalesce(l.principal_kind, CASE WHEN s.principal_name IS NOT NULL THEN 'service_account' END),
            sa_owner_team := s.owner_team, sa_privilege := s.privilege,
            sa_outside_expected_network := CASE WHEN s.principal_name IS NOT NULL
                                                THEN NOT starts_with(b.src_endpoint.ip, s.in_cluster_ip_prefix) END),
        src := struct_pack(
            reputation := r.reputation, category := r.category, as_org := r.as_org, asn := r.asn,
            country := r.country, tags := r.tags,
            cluster_internal := starts_with(b.src_endpoint.ip, split_part(c.node_cidr, '.', 1) || '.'
                                                              || split_part(c.node_cidr, '.', 2) || '.')),
        asset := struct_pack(environment := c.environment, data_classification := c.data_classification,
                             owner_team := c.owner_team),
        workload := CASE WHEN b.api.operation = 'create' AND b.resources[1].type = 'pods' THEN struct_pack(
            image := json_extract_string(b.req, '$.spec.containers[0].image'),
            privileged := json_extract_string(b.req, '$.spec.containers[0].securityContext.privileged') = 'true',
            host_pid := json_extract_string(b.req, '$.spec.hostPID') = 'true',
            host_root_mounted := contains(coalesce(json_extract(b.req, '$.spec.volumes')::VARCHAR, ''), '"path":"/"'),
            approved_registry := EXISTS (SELECT 1 FROM approved_registries a
                                         WHERE starts_with(json_extract_string(b.req, '$.spec.containers[0].image'),
                                                           a.registry_prefix)),
            platform_allowlisted := w.owner_name IS NOT NULL, allowlist_justification := w.justification) END
    ) AS enrichment
FROM base b
LEFT JOIN identity_links l ON l.cloud_provider = b.cloud.provider AND l.principal_name = b.actor.user.name
LEFT JOIN identities i ON i.person_id = l.person_id
LEFT JOIN service_accounts s ON s.cloud_provider = b.cloud.provider AND s.principal_name = b.actor.user.name
LEFT JOIN ip_reputation r ON r.ip = b.src_endpoint.ip
LEFT JOIN clusters c ON c.cloud_provider = b.cloud.provider AND c.account_uid = b.cloud.account.uid
                    AND c.cluster_name = b.cloud.account.labels['cluster_name']
LEFT JOIN privileged_allowlist w
       ON w.cloud_provider = b.cloud.provider AND w.namespace = b.resources[1].namespace
      AND w.owner_name = json_extract_string(b.req, '$.metadata.ownerReferences[0].name')
      AND starts_with(json_extract_string(b.req, '$.spec.containers[0].image'), w.image_prefix)
"""

TABLE = {"ocsf": "ocsf_api_activity", "enriched": "ocsf_enriched"}


def open_db(mode):
    """Materialize everything, then cut off file access so agent SQL can only read these tables."""
    con = connect(mappers=(mode in TABLE), mapper_path=ROOT / "solutions" / "lab2_ocsf")
    # Several agents may run side by side; keep each one's DuckDB from claiming most of the machine.
    con.sql("SET memory_limit = '25GB'")
    if mode == "enriched":
        con.sql(ENRICHED_VIEW)
    views = [r[0] for r in con.sql("SELECT view_name FROM duckdb_views() WHERE NOT internal").fetchall()]
    keep = {"raw": lambda v: v.startswith("raw_"), "ocsf": lambda v: v == "ocsf_api_activity",
            "enriched": lambda v: v == "ocsf_enriched"}[mode]
    # Enriched mode gets no fixture tables: the context is already on every row.
    fixtures = [] if mode == "enriched" else [p.stem for p in FIXTURES.glob("*.csv")]
    for v in views:
        if keep(v) or v in fixtures:
            con.sql(f"CREATE TABLE t_{v} AS SELECT * FROM {v}")
    for v in views:
        con.sql(f"DROP VIEW IF EXISTS {v} CASCADE")
    for t in [r[0] for r in con.sql("SELECT table_name FROM duckdb_tables()").fetchall()]:
        con.sql(f"ALTER TABLE {t} RENAME TO {t[2:]}")
    con.sql("SET enable_external_access = false")
    con.sql("SET lock_configuration = true")
    return con


READ_ONLY = re.compile(r"^\s*(with|select|from|describe|summarize|show)\b", re.I)


def run_sql(con, sql, max_rows=MAX_ROWS):
    if not READ_ONLY.match(sql) or ";" in sql.strip().rstrip(";"):
        raise ValueError("only a single read-only SELECT/WITH/DESCRIBE statement is allowed")
    timer = threading.Timer(QUERY_TIMEOUT_S, con.interrupt)
    timer.start()
    try:
        rel = con.sql(sql.strip().rstrip(";"))
        cols = rel.columns
        rows = rel.fetchmany(max_rows + 1)
    finally:
        timer.cancel()
    out = {"columns": cols, "rows": [[_jsonable(v) for v in r] for r in rows[:max_rows]]}
    if len(rows) > max_rows:
        out["truncated"] = f"more than {max_rows} rows; add filters or aggregate"
    return out


def _jsonable(v):
    if isinstance(v, (str, int, float, bool)) or v is None:
        return v
    if isinstance(v, (dict, list)):
        return json.loads(json.dumps(v, default=str))
    return str(v)


def render(result):
    text = json.dumps(result, default=str, separators=(",", ":"))
    if len(text) > MAX_CHARS:
        text = text[:MAX_CHARS] + f'... [output truncated at {MAX_CHARS} chars; narrow the query]'
    return text


# ---------------------------------------------------------------------------
# Tool schemas
# ---------------------------------------------------------------------------

def _tool(name, description, properties, required=()):
    return {"name": name, "description": description, "strict": True,
            "input_schema": {"type": "object", "properties": properties, "required": list(required),
                             "additionalProperties": False}}


def _nullable(t, description):
    return {"type": [t, "null"], "description": description}


SQL_TOOL = _tool(
    "query_sql",
    "Run one read-only DuckDB SQL query (SELECT/WITH/DESCRIBE/SUMMARIZE). Returns at most 50 rows; "
    "output over 12k characters is truncated. Call list_tables first to see what exists.",
    {"sql": {"type": "string", "description": "A single DuckDB SQL statement."}},
    ["sql"],
)
LIST_TABLES_TOOL = _tool("list_tables", "List available tables with their columns and row counts.", {})

SUBMIT_TOOL = _tool(
    "submit_verdict",
    "Submit the final investigation result. Call exactly once, when done; the investigation ends.",
    {
        "verdict": {"type": "string", "enum": ["malicious", "suspicious", "benign", "inconclusive"]},
        "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
        "summary": {"type": "string", "description": "3-6 sentence narrative of what happened."},
        "affected_clouds": {"type": "array", "items": {"type": "string", "enum": ["AWS", "GCP", "Azure"]}},
        "attacker_ips": {"type": "array", "items": {"type": "string"}},
        "compromised_principals": {"type": "array", "items": {"type": "string"},
                                   "description": "Native principal names as they appear in the logs."},
        "evidence": {
            "type": "array",
            "description": "Malicious events, each identified by its audit event ID "
                           "(auditID, or operation.id on GKE; metadata.uid in OCSF).",
            "items": {"type": "object", "additionalProperties": False,
                      "required": ["event_id", "cloud", "description"],
                      "properties": {"event_id": {"type": "string"},
                                     "cloud": {"type": "string", "enum": ["AWS", "GCP", "Azure"]},
                                     "description": {"type": "string"}}},
        },
        "benign_lookalikes": {"type": "array", "items": {"type": "string"},
                              "description": "Activity you examined and ruled benign, and why."},
    },
    ["verdict", "confidence", "summary", "affected_clouds", "attacker_ips", "compromised_principals",
     "evidence", "benign_lookalikes"],
)

OCSF_TOOLS = [
    _tool(
        "search_activity",
        "Search normalized Kubernetes API activity (OCSF API Activity) across AWS, GCP and Azure. "
        "All filters are optional and ANDed; returns newest-last compact rows with event_id (metadata.uid).",
        {
            "principal": _nullable("string", "Exact actor.user.name (native principal)."),
            "email": _nullable("string", "actor.user.email_addr - the human behind the principal."),
            "src_ip": _nullable("string", "src_endpoint.ip"),
            "cloud": _nullable("string", "AWS, GCP or Azure"),
            "operation": _nullable("string", "Kubernetes verb: get, list, create, update, patch, delete..."),
            "resource_type": _nullable("string", "e.g. pods, pods/exec, secrets, clusterrolebindings"),
            "namespace": _nullable("string", "Kubernetes namespace"),
            "status": _nullable("string", "Success or Failure"),
            "start": _nullable("string", "ISO-8601 lower bound on time"),
            "end": _nullable("string", "ISO-8601 upper bound on time"),
            "limit": _nullable("integer", "Max rows (default 50, max 50)"),
        },
        ["principal", "email", "src_ip", "cloud", "operation", "resource_type", "namespace", "status",
         "start", "end", "limit"],
    ),
    _tool(
        "summarize_activity",
        "Aggregate normalized activity: counts grouped by the chosen dimensions, with first/last seen. "
        "Use to find unusual principals, IPs or operations before drilling in.",
        {
            "group_by": {"type": "array", "items": {"type": "string", "enum": [
                "cloud", "principal", "email", "src_ip", "operation", "resource_type", "namespace",
                "status", "user_type"]}},
            "email": _nullable("string", "Optional filter on actor.user.email_addr"),
            "src_ip": _nullable("string", "Optional filter on src_endpoint.ip"),
        },
        ["group_by", "email", "src_ip"],
    ),
    _tool("get_event", "Full normalized record for one event, including the request body (truncated).",
          {"event_id": {"type": "string"}}, ["event_id"]),
    _tool("resolve_identity",
          "Resolve a person, email or native principal to the HR record and every linked cloud principal.",
          {"query": {"type": "string", "description": "Email, name, person_id or native principal."}},
          ["query"]),
    _tool("lookup_ip", "Reputation and ownership for an IP address; also flags cluster-internal addresses.",
          {"ip": {"type": "string"}}, ["ip"]),
    _tool("get_service_account",
          "Owner, privilege and expected source network for a Kubernetes service account.",
          {"principal": {"type": "string", "description": "system:serviceaccount:<ns>:<name>"}}, ["principal"]),
    _tool("list_clusters", "Cluster inventory: cloud, account, region, environment, data classification.", {}),
    _tool("check_privileged_workload",
          "Check whether a privileged pod matches the approved platform allowlist and approved registries.",
          {"event_id": {"type": "string", "description": "event_id of the pod create"}}, ["event_id"]),
    SQL_TOOL | {"description": SQL_TOOL["description"] + " Tables: ocsf_api_activity (nested OCSF structs; "
                "DuckDB lists are 1-indexed, e.g. resources[1].type) plus the enrichment tables."},
    LIST_TABLES_TOOL,
]

ENRICHED_DIMENSION_NAMES = ["cloud", "principal", "email", "src_ip", "operation", "resource_type", "namespace",
                            "status", "user_type", "person", "out_of_office", "client_os_mismatch",
                            "sa_outside_expected_network", "ip_reputation", "ip_category", "platform_allowlisted"]


def _enriched_tools():
    by_name = {t["name"]: t for t in OCSF_TOOLS}
    search = by_name["search_activity"] | {"description":
        "Search normalized, enriched Kubernetes API activity across AWS, GCP and Azure. All filters optional and "
        "ANDed. Every row already carries its context: the person behind the principal (name, out-of-office, "
        "client-OS mismatch), service-account network expectations, source IP reputation, and for pod creates "
        "whether the workload is privileged/allowlisted/from an approved registry."}
    summarize = copy.deepcopy(by_name["summarize_activity"])
    summarize["description"] = ("Aggregate enriched activity: counts grouped by the chosen dimensions, with "
                                "first/last seen. Enrichment dimensions let you pivot on context directly.")
    summarize["input_schema"]["properties"]["group_by"]["items"]["enum"] = ENRICHED_DIMENSION_NAMES
    get_event = by_name["get_event"] | {"description": "Full enriched record for one event, including the "
                                                         "request body (truncated) and all enrichment context."}
    sql = SQL_TOOL | {"description": SQL_TOOL["description"] + " Table: ocsf_enriched (nested OCSF structs plus "
                      "an `enrichment` struct with actor/src/asset/workload context; DuckDB lists are 1-indexed, "
                      "e.g. resources[1].type)."}
    return [search, summarize, get_event, sql, LIST_TABLES_TOOL]


RAW_TOOLS = [
    SQL_TOOL | {"description": SQL_TOOL["description"] + " Tables hold each cloud's audit log export "
                "exactly as delivered, plus enrichment tables."},
    LIST_TABLES_TOOL,
]


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

COMPACT = """metadata.uid AS event_id, strftime(time, '%Y-%m-%dT%H:%M:%S') AS time, cloud.provider AS cloud,
    actor.user.name AS principal, actor.user.email_addr AS email, src_endpoint.ip AS src_ip,
    api.operation AS operation, resources[1].type AS resource_type, resources[1].namespace AS namespace,
    resources[1].name AS name, status, http_request.user_agent AS user_agent"""

ENRICHED_COMPACT = COMPACT + """, enrichment.actor.full_name AS person,
    enrichment.actor.out_of_office AS out_of_office, enrichment.actor.client_os_mismatch AS client_os_mismatch,
    enrichment.actor.sa_outside_expected_network AS sa_outside_expected_network,
    enrichment.src.reputation AS ip_reputation, enrichment.src.as_org AS ip_as_org,
    enrichment.workload.privileged AS privileged_pod, enrichment.workload.platform_allowlisted AS platform_allowlisted"""

DIMENSIONS = {"cloud": "cloud.provider", "principal": "actor.user.name", "email": "actor.user.email_addr",
              "src_ip": "src_endpoint.ip", "operation": "api.operation", "resource_type": "resources[1].type",
              "namespace": "resources[1].namespace", "status": "status", "user_type": "actor.user.type",
              "person": "enrichment.actor.full_name", "out_of_office": "enrichment.actor.out_of_office",
              "client_os_mismatch": "enrichment.actor.client_os_mismatch",
              "sa_outside_expected_network": "enrichment.actor.sa_outside_expected_network",
              "ip_reputation": "enrichment.src.reputation", "ip_category": "enrichment.src.category",
              "platform_allowlisted": "enrichment.workload.platform_allowlisted"}


class Tools:
    def __init__(self, mode):
        self.mode = mode
        self.con = open_db(mode)
        self.table = TABLE.get(mode)
        self.compact = ENRICHED_COMPACT if mode == "enriched" else COMPACT
        tools = {"raw": RAW_TOOLS, "ocsf": OCSF_TOOLS, "enriched": _enriched_tools()}[mode]
        self.schemas = tools + [SUBMIT_TOOL]

    def call(self, name, args):
        fn = getattr(self, f"t_{name}", None)
        if fn is None or name not in {s["name"] for s in self.schemas}:
            raise ValueError(f"unknown tool {name}")
        return render(fn(**args))

    def _params(self, sql, params):
        return [list(r) for r in self.con.execute(sql, params).fetchall()]

    def t_query_sql(self, sql):
        return run_sql(self.con, sql)

    def t_list_tables(self):
        out = []
        for (t,) in self.con.sql("SELECT table_name FROM duckdb_tables() ORDER BY 1").fetchall():
            cols = self.con.sql(f"DESCRIBE {t}").fetchall()
            n = self.con.sql(f"SELECT count(*) FROM {t}").fetchone()[0]
            out.append({"table": t, "rows": n, "columns": {c[0]: c[1][:200] for c in cols}})
        return out

    def t_search_activity(self, principal, email, src_ip, cloud, operation, resource_type, namespace,
                          status, start, end, limit):
        filters = {"actor.user.name": principal, "actor.user.email_addr": email, "src_endpoint.ip": src_ip,
                   "cloud.provider": cloud, "api.operation": operation, "resources[1].type": resource_type,
                   "resources[1].namespace": namespace, "status": status}
        where, params = [], []
        for col, val in filters.items():
            if val is not None:
                where.append(f"{col} = ?")
                params.append(val)
        if start:
            where.append("time >= ?::TIMESTAMPTZ")
            params.append(start)
        if end:
            where.append("time <= ?::TIMESTAMPTZ")
            params.append(end)
        n = min(limit or MAX_ROWS, MAX_ROWS)
        sql = (f"SELECT {self.compact} FROM {self.table} {'WHERE ' + ' AND '.join(where) if where else ''} "
               f"ORDER BY time")
        total = self.con.execute(f"SELECT count(*) FROM ({sql})", params).fetchone()[0]
        rows = self.con.execute(sql + f" LIMIT {n}", params)
        cols = [d[0] for d in rows.description]
        result = {"total_matches": total, "columns": cols, "rows": [list(r) for r in rows.fetchall()]}
        if total > n:
            result["note"] = f"showing first {n} of {total}; narrow filters or use summarize_activity"
        return result

    def t_summarize_activity(self, group_by, email, src_ip):
        dims = group_by or ["cloud"]
        sel = ", ".join(f"{DIMENSIONS[d]} AS {d}" for d in dims)
        where, params = [], []
        if email:
            where.append("actor.user.email_addr = ?")
            params.append(email)
        if src_ip:
            where.append("src_endpoint.ip = ?")
            params.append(src_ip)
        sql = (f"SELECT {sel}, count(*) AS events, strftime(min(time), '%H:%M:%S') AS first_seen, "
               f"strftime(max(time), '%H:%M:%S') AS last_seen FROM {self.table} "
               f"{'WHERE ' + ' AND '.join(where) if where else ''} GROUP BY ALL ORDER BY events DESC LIMIT 100")
        rows = self.con.execute(sql, params)
        return {"columns": [d[0] for d in rows.description], "rows": [list(r) for r in rows.fetchall()]}

    def t_get_event(self, event_id):
        row = self.con.execute(f"SELECT to_json(t) FROM {self.table} t WHERE metadata.uid = ?",
                               [event_id]).fetchone()
        if not row:
            return {"error": f"no event {event_id}"}
        ev = json.loads(row[0])
        for side in ("request", "response"):
            data = ev["api"][side].get("data")
            if data is not None:
                ev["api"][side]["data"] = json.dumps(data)[:3000]
        return ev

    def t_resolve_identity(self, query):
        person = self._params("""
            SELECT DISTINCT i.* FROM identities i LEFT JOIN identity_links l USING (person_id)
            WHERE ? IN (i.email, i.display_name, i.person_id, l.principal_name, l.principal_uid)""", [query])
        ids = [p[0] for p in person] or [query]
        links = self._params("SELECT * FROM identity_links WHERE person_id IN (SELECT unnest(?)) "
                             "OR principal_name = ?", [ids, query])
        cols = [c[0] for c in self.con.sql("DESCRIBE identities").fetchall()]
        return {"person": [dict(zip(cols, p)) for p in person] or None,
                "linked_principals": [dict(zip(["person_id", "cloud_provider", "principal_name", "principal_uid",
                                                "principal_kind"], l)) for l in links]}

    def t_lookup_ip(self, ip):
        rep = self.con.execute("SELECT * FROM ip_reputation WHERE ip = ?", [ip])
        cols = [d[0] for d in rep.description]
        hit = rep.fetchone()
        internal = self._params("SELECT cloud_provider, cluster_name, node_cidr FROM clusters "
                                "WHERE starts_with(?, split_part(node_cidr, '.', 1) || '.' || "
                                "split_part(node_cidr, '.', 2) || '.')", [ip])
        return {"reputation": dict(zip(cols, hit)) if hit else None,
                "cluster_internal": [dict(zip(["cloud_provider", "cluster_name", "node_cidr"], r)) for r in internal],
                "note": None if hit or internal else "no reputation data for this IP"}

    def t_get_service_account(self, principal):
        rows = self.con.execute("SELECT * FROM service_accounts WHERE principal_name = ?", [principal])
        cols = [d[0] for d in rows.description]
        return [dict(zip(cols, r)) for r in rows.fetchall()] or {"error": "unknown service account"}

    def t_list_clusters(self):
        rows = self.con.sql("SELECT * FROM clusters")
        return [dict(zip(rows.columns, r)) for r in rows.fetchall()]

    def t_check_privileged_workload(self, event_id):
        row = self.con.execute("""
            SELECT cloud.provider, resources[1].namespace,
                   api.request.data->>'$.metadata.ownerReferences[0].name',
                   api.request.data->>'$.spec.containers[0].image',
                   api.request.data->>'$.spec.containers[0].securityContext.privileged',
                   api.request.data->>'$.spec.hostPID', api.request.data->'$.spec.volumes'
            FROM ocsf_api_activity WHERE metadata.uid = ?""", [event_id]).fetchone()
        if not row:
            return {"error": f"no event {event_id}"}
        provider, ns, owner, image, privileged, host_pid, volumes = row
        allowed = self._params("""SELECT justification FROM privileged_allowlist WHERE cloud_provider = ?
                                  AND namespace = ? AND owner_name = ? AND starts_with(?, image_prefix)""",
                               [provider, ns, owner, image or ""])
        registry = self._params("SELECT registry_prefix FROM approved_registries WHERE starts_with(?, registry_prefix)",
                                [image or ""])
        return {"cloud": provider, "namespace": ns, "owner": owner, "image": image, "privileged": privileged,
                "host_pid": host_pid, "volumes": volumes, "on_platform_allowlist": bool(allowed),
                "allowlist_justification": allowed[0][0] if allowed else None,
                "image_from_approved_registry": bool(registry)}

    def t_submit_verdict(self, **verdict):
        return {"status": "received"}
