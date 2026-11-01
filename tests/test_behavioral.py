"""Offline detection, provenance and agent-tool regression tests (no model or network)."""

import copy
import json
from pathlib import Path
import tempfile
import unittest

from agent.evaluate_triage import score
from agent.triage import Investigation, run, safe_select, snapshot, observed_event_ids, enriched_severity
from datagen.build_behavioral import build
from datagen.make_sql_notebooks import evaluation
from workshop.behavioral import ROOT, participant_macro_sql, statements
from workshop.engine import Database
from workshop.notebooks import seed_sql


class BehavioralTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="behavioral-tests-")
        cls.db = Database(Path(cls.tmp.name) / "lab.duckdb")
        cls.db.script(";\n".join(statements() + [participant_macro_sql()]) + ";")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def alert_key(self, scenario, split="training"):
        cases = json.loads((ROOT / "data" / "behavioral" / split / "cases.json").read_text())
        return next(c["alert_event_ids"][0] for c in cases if c["scenario"] == scenario)

    def test_corpus_reproducible(self):
        for split in ("training", "holdout"):
            for name, content in build(split).items():
                self.assertEqual(content, (ROOT / "data" / "behavioral" / split / name).read_bytes(), name)

    def test_reference_matches_each_expected_alert_key(self):
        for split in ("training", "holdout"):
            rows = self.db.query(f"""SELECT l.* FROM {split}.evaluation_labels l
                LEFT JOIN {split}.behavioral_candidates c USING(alert_key)
                WHERE (c.alert_key IS NOT NULL) IS DISTINCT FROM l.expected_match::BOOLEAN""")
            self.assertEqual(rows, [])

    def test_tuned_precision_recall_both_splits(self):
        for split in ("training", "holdout"):
            row = self.db.query(f"SELECT * FROM {split}.detection_metrics")[0]
            self.assertEqual((row["fp"], row["fn"], row["unobservable_cases"]), (0, 0, 6))
            self.assertEqual((row["precision"], row["recall_observable"]), (1, 1))

    def test_one_macro_runs_unchanged_on_both_splits(self):
        for split in ("training", "holdout"):
            rows = self.db.query(f"""(SELECT alert_key FROM main.participant_rule('{split}.events','{split}.identities','{split}.approvals')
                EXCEPT SELECT alert_key FROM {split}.behavioral_alerts)
                UNION ALL (SELECT alert_key FROM {split}.behavioral_alerts
                EXCEPT SELECT alert_key FROM main.participant_rule('{split}.events','{split}.identities','{split}.approvals'))""")
            self.assertEqual(rows, [])

    def test_evaluator_counts_unlabeled_outputs_as_false_positives(self):
        self.db.script("CREATE OR REPLACE MACRO main.unknown_rule(a,b,c) AS TABLE SELECT 'not-in-the-label-set' AS alert_key;")
        result = self.db.query(evaluation("training").replace("main.participant_rule", "main.unknown_rule"))[0]
        self.assertEqual((result["tp"], result["fp"], result["fn"], result["out_of_scope_alerts"]), (0, 1, 16, 1))

    def test_cross_cloud_campaigns_require_identity_and_two_clouds(self):
        rows = self.db.query("SELECT * FROM training.cross_cloud_campaigns")
        self.assertEqual(len(rows), 4)
        self.assertTrue(all(r["provider_count"] == 3 for r in rows))
        self.assertNotIn("person-815-10", {r["person_id"] for r in rows})

    def test_deduplication(self):
        row = self.db.query("SELECT (SELECT count(*) FROM training.event_cache) - (SELECT count(*) FROM training.events) AS duplicates")[0]
        self.assertEqual(row["duplicates"], 6)
        self.assertEqual(self.db.query("SELECT max(read_events) AS n FROM training.behavioral_candidates")[0]["n"], 1)

    def test_holdout_has_structurally_new_cases(self):
        cases = json.loads((ROOT / "data/behavioral/holdout/cases.json").read_text())
        self.assertTrue({"boundary_inclusive", "boundary_exceeded", "namespaced_read", "other_account"} <= {c["scenario"] for c in cases})

    def test_nullable_time_does_not_match(self):
        # Temporary schema with the same reference macro and a lost event-time field.
        self.db.script("CREATE OR REPLACE VIEW training.null_times AS SELECT * REPLACE(NULL::TIMESTAMPTZ AS time) FROM training.events;")
        row = self.db.query("SELECT count(*) AS n FROM main.participant_rule('training.null_times','training.identities','training.approvals')")[0]
        self.assertEqual(row["n"], 0)

    def test_snapshots_do_not_contain_labels_or_external_views(self):
        with tempfile.TemporaryDirectory() as directory:
            db = snapshot(self.db, Path(directory) / "agent.duckdb")
            tables = {r["table_name"] for r in db.query("SELECT table_name FROM information_schema.tables")}
            self.assertEqual(tables, {"events", "identities", "ip_enrichment", "user_enrichment", "k8s_cluster_enrichment", "approvals"})
            with self.assertRaises(RuntimeError):
                db.query("SELECT * FROM read_csv('/etc/hosts')", restricted=True)

    def test_enrichment_changes_severity_without_changing_alert_membership(self):
        for split in ("training", "holdout"):
            rows = self.db.query(f"SELECT * FROM {split}.behavioral_alerts")
            self.assertEqual({r["severity"] for r in rows}, {"low", "medium", "high", "critical"})
            self.assertTrue(all(r["base_severity"] == "high" for r in rows))
            neutral = next(r for r in rows if r["alert_key"] == self.alert_key("duplicate_stage", split))
            self.assertEqual((neutral["severity"], neutral["severity_reasons"]), ("high", []))
            # Independent triage and SQL must explain the same policy on every real alert.
            for row in rows:
                ips = self.db.query(f"SELECT * FROM {split}.ip_enrichment")
                ips = [i for i in ips if i["ip_address"] in row["source_ips"]]
                users = self.db.query(f"SELECT * FROM {split}.user_enrichment")
                users = [u for u in users if u["cloud_provider"] == row["provider"] and u["account_uid"] == row["account_uid"] and u["principal_name"] == row["subject"]]
                clusters = self.db.query(f"SELECT * FROM {split}.k8s_cluster_enrichment")
                clusters = [k for k in clusters if k["cloud_provider"] == row["provider"] and k["account_uid"] == row["account_uid"] and k["cluster_name"] == row["cluster_name"]]
                self.assertEqual(enriched_severity(ips, users, clusters, set(row["source_ips"])), (row["severity"], row["severity_reasons"]))

    def test_ip_enrichment_contract_and_address_metadata(self):
        import ipaddress
        from datagen.build_behavioral import IP_FIELDS
        for split in ("training", "holdout"):
            rows = self.db.query(f"SELECT * FROM {split}.ip_enrichment")
            self.assertEqual(set(rows[0]), set(IP_FIELDS))
            self.assertEqual(len(rows), len({r["ip_address"] for r in rows}))
            self.assertEqual({r["ip_version"] for r in rows}, {"IPv4", "IPv6"})
            for row in rows:
                address = ipaddress.ip_address(row["ip_address"])
                self.assertEqual(row["ip_version"], f"IPv{address.version}")
                self.assertEqual(row["bogon_or_private"], not address.is_global)
                self.assertIsInstance(row["reputation_score"], int)
                self.assertTrue(0 <= row["reputation_score"] <= 100)
                self.assertEqual(row["is_malicious"], row["reputation"] == "malicious")
                for field in ("bogon_or_private", "is_malicious", "is_vpn", "is_proxy", "is_tor", "is_hosting", "is_cloud"):
                    self.assertIsInstance(row[field], bool)
            # An anonymization flag alone does not classify an address as malicious.
            self.assertTrue(any(r["is_tor"] and not r["is_malicious"] for r in rows))
            internal = next(r for r in rows if r["ip_address"] == "10.0.0.10")
            self.assertIsNone(internal["asn"])
            self.assertIsNone(internal["country_code"])

    def test_participant_enrichment_uses_scoped_context_and_retains_missing_matches(self):
        self.db.script("""
            CREATE OR REPLACE VIEW main.policy_alerts AS
              SELECT * FROM main.participant_rule('training.events','training.identities','training.approvals')
              WHERE subject LIKE '%analyst815@example.com%';
            CREATE OR REPLACE VIEW main.empty_ips AS SELECT * FROM training.ip_enrichment WHERE false;
            CREATE OR REPLACE VIEW main.empty_clusters AS SELECT * FROM training.k8s_cluster_enrichment WHERE false;
            CREATE OR REPLACE TABLE main.policy_users AS SELECT * FROM training.user_enrichment WHERE false;
        """)
        query = "SELECT severity FROM main.enrich_alerts('main.policy_alerts','main.empty_ips','main.policy_users','main.empty_clusters')"
        self.assertEqual(self.db.query(query), [{"severity": "high"}] * 3)
        self.db.script("""INSERT INTO main.policy_users
            SELECT u.* REPLACE ('wrong-account' AS account_uid)
            FROM training.user_enrichment u JOIN main.policy_alerts a
            ON u.cloud_provider=a.provider AND u.account_uid=a.account_uid AND u.principal_name=a.subject;""")
        self.assertEqual(self.db.query(query), [{"severity": "high"}] * 3)
        self.db.script("""DELETE FROM main.policy_users;
            INSERT INTO main.policy_users SELECT u.* FROM training.user_enrichment u JOIN main.policy_alerts a
            ON u.cloud_provider=a.provider AND u.account_uid=a.account_uid AND u.principal_name=a.subject;""")
        self.assertEqual(self.db.query(query), [{"severity": "critical"}] * 3)
        self.db.script("UPDATE main.policy_users SET employment_status='active', is_privileged_admin='true';")
        self.assertEqual(self.db.query(query), [{"severity": "medium"}] * 3)

    def test_workshop_sql_uses_relational_views_and_standard_constructs(self):
        import re
        from datagen.make_sql_notebooks import notebooks
        texts = [sql for cells in notebooks().values() for sql in cells]
        texts += [p.read_text() for p in (ROOT / 'detection').glob('*.sql')]
        for text in texts:
            self.assertIsNone(re.search(r'CREATE\s+(?:OR\s+REPLACE\s+)?MACRO|query_table\s*\(|list_\w+\s*\(|GROUP BY ALL|SELECT\s+\*\s+(?:REPLACE|EXCLUDE)|QUALIFY|::|json_each\s*\(', text, re.I), text)

    def test_plain_sql_views_preserve_detection_and_severity(self):
        from workshop.behavioral import enterprise_statements, participant_view_sql
        projection = ';'.join(s for s in enterprise_statements()
                              if 'CREATE OR REPLACE TABLE k8s_ocsf' in s or 'CREATE OR REPLACE TABLE k8s_subjects' in s)
        for split in ('training', 'holdout'):
            self.db.script(f"SET schema='{split}';" + projection + ";SET schema='main';" +
                           participant_view_sql().replace('enterprise.', split + '.') + ';' +
                           (ROOT / 'detection/alert_evidence.sql').read_text().replace('enterprise.', split + '.') +
                           (ROOT / 'detection/enrich_alerts.sql').read_text().replace('enterprise.', split + '.'))
            reference = self.db.query(f"SELECT alert_key, subject, first_read, last_read, read_events, person_id, severity FROM {split}.behavioral_alerts ORDER BY alert_key, subject")
            actual = self.db.query("SELECT alert_key, subject, first_read, last_read, read_events, person_id, severity FROM main.enriched_alerts ORDER BY alert_key, subject")
            self.assertEqual(actual, reference)
            missing = self.db.query("""SELECT a.alert_key FROM main.workshop_alerts a LEFT JOIN main.alert_evidence e
              ON e.alert_key=a.alert_key AND e.subject=a.subject
              GROUP BY a.alert_key, a.subject, a.read_events
              HAVING COUNT(DISTINCT e.event_id) != a.read_events + 1""")
            self.assertEqual(missing, [])

    def test_missing_and_mixed_ip_enrichment_cannot_lower_severity(self):
        corporate = {"ip_address": "192.0.2.1", "network_type": "corporate_vpn", "is_malicious": False}
        malicious = {"ip_address": "192.0.2.2", "network_type": "corporate_vpn", "is_malicious": True}
        self.assertEqual(enriched_severity([], [], [], {"192.0.2.1"}), ("high", []))
        self.assertEqual(enriched_severity([corporate], [], [], {"192.0.2.1", "192.0.2.2"}), ("high", []))
        self.assertEqual(enriched_severity([corporate], [], [], {"192.0.2.1"})[0], "medium")
        self.assertEqual(enriched_severity([corporate, malicious], [], [], {"192.0.2.1", "192.0.2.2"})[0], "critical")

    def test_read_only_guard(self):
        for sql in ("ATTACH 'a' AS a", "SELECT 1; DROP TABLE events", "WITH a AS (SELECT 1) SELECT * FROM a; SELECT 2"):
            with self.assertRaises(ValueError):
                safe_select(sql)
        self.assertEqual(safe_select("SELECT ';' AS punctuation;"), "SELECT ';' AS punctuation")

    def test_raw_and_ocsf_returned_id_provenance(self):
        self.assertEqual(observed_event_ids({"event": '{"auditID":"eks-event"}'}), {"eks-event"})
        self.assertEqual(observed_event_ids({"entry": {"protoPayload": {}, "operation": {"id": "gke-event"}}}), {"gke-event"})
        self.assertEqual(observed_event_ids({"api": {}, "metadata": {"uid": "ocsf-event"}}), {"ocsf-event"})

    def test_replay_supported_claims(self):
        record = run(self.db, self.alert_key("compromise"))
        result = score(self.db, record)
        self.assertTrue(result["decision_correct"])
        expected = self.db.query("SELECT severity, severity_reasons FROM training.behavioral_alerts WHERE alert_key='" + record["alert_key"] + "'")[0]
        self.assertEqual(record["assessment"]["severity"], expected["severity"])
        self.assertEqual(record["assessment"]["severity_reasons"], expected["severity_reasons"])
        self.assertEqual(result["claim_support_precision"], 1)
        self.assertEqual(result["required_evidence_covered"], result["required_evidence_total"])

    def test_missing_evidence_and_identity_are_inconclusive(self):
        for case in ("missing_reads", "missing_request"):
            record = run(self.db, self.alert_key(case))
            self.assertEqual(record["assessment"]["disposition"], "inconclusive")
            self.assertTrue(record["assessment"]["uncertainties"])

    def test_unresolved_identity_keeps_native_behavior_but_limits_attribution(self):
        record = run(self.db, self.alert_key("unresolved_identity"))
        self.assertEqual(record["assessment"]["disposition"], "suspicious")
        self.assertEqual(record["assessment"]["attribution"], "native_only")
        self.assertTrue(record["assessment"]["claims"])

    def test_tool_repair_changes_wrong_cluster_verdict(self):
        alert_key = self.alert_key("wrong_cluster")
        broken = run(self.db, alert_key, timeline_sql=ROOT / "labs/behavioral/timeline.sql")
        fixed = run(self.db, alert_key, timeline_sql=ROOT / "solutions/behavioral/timeline.sql")
        self.assertFalse(score(self.db, broken)["decision_correct"])
        self.assertTrue(score(self.db, fixed)["decision_correct"])
        self.assertLess(score(self.db, broken)["claim_support_precision"], 1)

    def test_scorer_rejects_invented_and_unobserved_evidence(self):
        record = run(self.db, self.alert_key("compromise"))
        bad = copy.deepcopy(record)
        bad["assessment"]["claims"].append({"kind": "secret_list", "event_id": "invented", "explanation": "unsupported"})
        self.assertEqual(score(self.db, bad)["invented_event_ids"], 1)
        bad = copy.deepcopy(record)
        bad["trace"] = []
        self.assertGreater(score(self.db, bad)["unobserved_event_ids"], 0)

    def test_native_notebook_seed_is_idempotent_and_preserves_edits(self):
        directory = Path(self.tmp.name) / "ui"
        sql = ";\n".join(seed_sql("lab", directory)) + ";"
        self.db.script(sql + "DETACH _duckdb_ui;")
        ui = Database(directory / "ui.db")
        row = ui.query("SELECT notebook_id FROM notebook_versions LIMIT 1")[0]
        ui.script("UPDATE notebook_versions SET title='participant edit' WHERE notebook_id='" + row["notebook_id"] + "';")
        self.db.script(sql + "DETACH _duckdb_ui;")
        self.assertEqual(ui.query("SELECT count(*) AS n FROM notebooks")[0]["n"], 6)
        self.assertEqual(ui.query("SELECT count(*) AS n FROM notebook_versions WHERE title='participant edit'")[0]["n"], 1)
        payload = json.loads(ui.query("SELECT json FROM notebook_versions LIMIT 1")[0]["json"])
        self.assertEqual(payload["notebookSerializationFormat"], 3)
        self.assertTrue(all(c["useDatabase"] == "lab" for c in payload["cells"]))


if __name__ == "__main__":
    unittest.main()
