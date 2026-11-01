"""Build behavioral lab SQL without requiring the DuckDB Python package."""

import argparse
from pathlib import Path

from workshop.db import CLOUDS, MACROS, OCSF_API_ACTIVITY, RAW, RAW_VIEWS, ROOT

CORPUS = ROOT / "data" / "behavioral"
RULE = ROOT / "tests" / "sql" / "reference_behavioral.sql"

EVENT_PROJECTION = """-- Flatten the OCSF record into the relational columns used by detection.
    -- Preserve source identity, event time and full asset scope alongside request evidence.
    SELECT metadata.uid AS event_id, time, cloud.provider AS provider,
    cloud.account.uid AS account_uid, cloud.account.labels['cluster_name'] AS cluster_name,
    actor.user.name AS principal, actor.user.email_addr AS email,
    api.operation AS operation, status_id, resources[1].type AS resource_type,
    resources[1].namespace AS namespace, resources[1].name AS resource_name,
    src_endpoint.ip AS src_ip, api.request.data AS request, http_request.url.path AS request_uri
    FROM {source}"""


def literal(value):
    return "'" + str(value).replace("'", "''") + "'"


def statements(include_evaluation=True):
    sql = [(ROOT / "tests" / "sql" / "reference_enrichment.sql").read_text().strip().rstrip(";")]
    for split in ("training", "holdout"):
        data = CORPUS / split
        sql += [f"CREATE SCHEMA IF NOT EXISTS {split}", f"SET schema = '{split}'"]
        sql += [m.replace("CREATE MACRO", "CREATE OR REPLACE MACRO", 1) for m in MACROS]
        for name, body in RAW_VIEWS.items():
            body = body.replace(str(RAW), str(data))
            sql.append(f"CREATE OR REPLACE VIEW {name} AS {body}")
        casts = ", ".join(f'CAST("{c}" AS {t}) AS "{c}"' for c, t in OCSF_API_ACTIVITY.items())
        for cloud in CLOUDS:
            body = (ROOT / "solutions" / "lab2_ocsf" / f"{cloud}.sql").read_text().strip().rstrip(";")
            sql += [f"CREATE OR REPLACE VIEW ocsf_{cloud}_uncast AS {body}",
                    f"CREATE OR REPLACE VIEW ocsf_{cloud} AS SELECT {casts} FROM ocsf_{cloud}_uncast"]
        sql.append("CREATE OR REPLACE VIEW ocsf_api_activity AS " + " UNION ALL BY NAME ".join(
            f"SELECT * FROM ocsf_{cloud}" for cloud in CLOUDS))
        # Materialize this small corpus only, keeping repeated rule evaluation inexpensive.
        sql += ["DROP TABLE IF EXISTS event_cache", "CREATE TABLE event_cache AS " + EVENT_PROJECTION.format(source="ocsf_api_activity"),
            """CREATE OR REPLACE VIEW events AS SELECT * FROM event_cache
            QUALIFY row_number() OVER (
              PARTITION BY provider, account_uid, cluster_name, event_id
              ORDER BY time NULLS LAST, status_id DESC) = 1"""]
        sql.append("DROP VIEW IF EXISTS coverage")
        for name in ("identities", "ip_enrichment", "user_enrichment", "k8s_cluster_enrichment", "approvals"):
            # IP risk scores and boolean flags remain typed for exploration and filtering.
            all_varchar = "false" if name == "ip_enrichment" else "true"
            sql.append(f"CREATE OR REPLACE VIEW {name} AS SELECT * FROM read_csv({literal(data / (name + '.csv'))}, all_varchar={all_varchar})")
        sql.append(RULE.read_text().strip().rstrip(";"))
        if include_evaluation:
            sql.append(f"CREATE OR REPLACE VIEW evaluation_labels AS SELECT * FROM read_csv({literal(data / 'labels.csv')}, all_varchar=true)")
            sql.append("""CREATE OR REPLACE VIEW detection_metrics AS
                -- Mark each labeled grant according to whether the reference rule emitted it.
                -- This internal evaluation is separate from participant detection and enrichment.
                WITH results AS (
                    SELECT l.*, a.alert_key IS NOT NULL AS alerted
                    FROM evaluation_labels l LEFT JOIN behavioral_alerts a USING (alert_key)
                ),
                -- Aggregate correct detections, false positives and observable misses.
                -- Keep unobservable cases separate so absent evidence is not scored as a miss.
                counts AS (
                    SELECT count(*) FILTER (WHERE alerted AND malicious::BOOLEAN) AS tp,
                           count(*) FILTER (WHERE alerted AND NOT malicious::BOOLEAN) AS fp,
                           count(*) FILTER (WHERE NOT alerted AND malicious::BOOLEAN AND observable::BOOLEAN) AS fn,
                           count(*) FILTER (WHERE NOT observable::BOOLEAN) AS unobservable_cases
                    FROM results
                ) SELECT *, tp::DOUBLE / nullif(tp + fp, 0) AS precision,
                            tp::DOUBLE / nullif(tp + fn, 0) AS recall_observable
                FROM counts""")
    sql.append("SET schema = 'main'")
    return sql


def participant_macro_sql():
    """A single editable table macro can be evaluated on either split, without rewriting SQL."""
    candidate = RULE.read_text().split(";", 1)[0].split(" AS\n", 1)[1]
    candidate = candidate.replace("FROM events e", "FROM query_table(event_table) e")
    candidate = candidate.replace("JOIN events r", "JOIN query_table(event_table) r")
    candidate = candidate.replace("JOIN identities i", "JOIN query_table(identity_table) i")
    return f"""CREATE OR REPLACE MACRO main.participant_rule(event_table, identity_table, approval_table) AS TABLE
    -- Run the internal reference sequence on the supplied event and identity tables.
    -- Keep this candidate relation separate from exact, time-scoped approval suppression.
    WITH candidates AS ({candidate})
    SELECT c.* FROM candidates c WHERE NOT EXISTS (
      SELECT 1 FROM query_table(approval_table) a
      WHERE a.cloud_provider=c.provider AND a.account_uid=c.account_uid AND a.cluster_name=c.cluster_name
        AND a.grant_actor=c.grant_actor AND a.subject=c.subject AND a.role=c.role
        AND c.grant_time BETWEEN a.start_time::TIMESTAMPTZ AND a.end_time::TIMESTAMPTZ
    )"""


def original_statements():
    """Run the identical rule on the original larger workshop dataset as corroboration."""
    return ["CREATE SCHEMA IF NOT EXISTS original", "SET schema='original'",
            "CREATE OR REPLACE VIEW events AS " + EVENT_PROJECTION.format(source="main.ocsf_api_activity"),
            """CREATE OR REPLACE VIEW identities AS
               SELECT l.person_id, l.cloud_provider, c.account_uid, l.principal_name
               FROM main.identity_links l JOIN main.clusters c ON c.cloud_provider=l.cloud_provider""",
            """CREATE OR REPLACE VIEW approvals AS SELECT NULL::VARCHAR AS cloud_provider,
               NULL::VARCHAR AS account_uid, NULL::VARCHAR AS cluster_name, NULL::VARCHAR AS grant_actor,
               NULL::VARCHAR AS subject, NULL::VARCHAR AS role,
               NULL::TIMESTAMPTZ AS start_time, NULL::TIMESTAMPTZ AS end_time WHERE false""",
            *[f"CREATE OR REPLACE VIEW {name} AS SELECT * FROM training.{name} WHERE false"
              for name in ("ip_enrichment", "user_enrichment", "k8s_cluster_enrichment")],
            RULE.read_text().strip().rstrip(";"), "SET schema='main'"]


def participant_view_sql():
    """The saved detection is a regular SQL view, with explicit table names."""
    return (ROOT / "detection" / "privilege_to_secrets.sql").read_text().strip().rstrip(";")


def enterprise_statements():
    """Engine-specific ingestion prepares relational inputs; teaching SQL uses regular views."""
    return [(ROOT / "workshop" / "enterprise.sql").read_text().strip().rstrip(";"),
            "DROP TABLE IF EXISTS event_cache",
            "CREATE TABLE event_cache AS " + EVENT_PROJECTION.format(source="main.ocsf_api_activity"),
            """CREATE OR REPLACE VIEW events AS
               -- Deduplicate delivery copies by source event ID within the full asset scope.
               -- Prefer earlier non-null event times, then the higher status value on a tie.
               SELECT event_id, time, provider, account_uid, cluster_name, principal, email,
                      operation, status_id, resource_type, namespace, resource_name, src_ip, request, request_uri
               FROM (
               SELECT *, ROW_NUMBER() OVER (PARTITION BY provider, account_uid, cluster_name, event_id
                 ORDER BY time NULLS LAST, status_id DESC) AS _row_number FROM event_cache
               ) ranked WHERE _row_number=1""",
            """CREATE OR REPLACE TABLE k8s_ocsf AS
               -- Expose every deduplicated Kubernetes event through one OCSF-derived relational schema.
               -- Project role references when present; non-RBAC events stay in the table with NULL role fields.
               SELECT e.*, json_extract_string(e.request, '$.roleRef.kind') AS role_kind,
                      json_extract_string(e.request, '$.roleRef.name') AS role
               FROM events e""",
            """CREATE OR REPLACE TABLE k8s_subjects AS
               -- Store repeated request subjects separately to preserve one row per event in k8s_ocsf.
               -- Retain full source keys so each granted subject joins back to the correct event.
               SELECT e.event_id, e.provider, e.account_uid, e.cluster_name,
                      json_extract_string(s.value, '$.kind') AS subject_kind,
                      json_extract_string(s.value, '$.name') AS subject
               FROM k8s_ocsf e, LATERAL json_each(json_extract(e.request, '$.subjects')) s""",
            participant_view_sql(),
            (ROOT / "detection" / "alert_evidence.sql").read_text().strip().rstrip(";"),
            (ROOT / "detection" / "enrich_alerts.sql").read_text().strip().rstrip(";"),
            "CREATE OR REPLACE VIEW enterprise.behavioral_alerts AS SELECT * FROM main.enriched_alerts",
            "SET schema='main'"]


def install(con):
    for statement in statements():
        con.execute(statement)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sql-out", type=Path, required=True)
    args = parser.parse_args()
    args.sql_out.write_text(";\n".join(statements()) + ";\n")
    print(args.sql_out)


if __name__ == "__main__":
    main()
