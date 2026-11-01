"""Smoke test: the Lab 1 raw privileged-pod rule, written once per cloud, finds the attack in each."""
import duckdb
con = duckdb.connect()
R = "read_json('data/raw/{0}/{0}_audit.jsonl.gz', maximum_object_size=67108864, format='newline_delimited')"
con.sql(f"create view eks as select json(le.message) m from (select unnest(logEvents) le from {R.format('eks')})")
con.sql(f"create view gke as select * from {R.format('gke')}")
con.sql(f"create view aks as select json(r.properties.log) m, r.time from (select unnest(records) r from {R.format('aks')})")
con.sql("create view gt as select * from read_csv('data/raw/ground_truth.csv')")
native = """select json_extract_string(m,'$.auditID') id, json_extract_string(m,'$.user.username') who from {t}
 where json_extract_string(m,'$.verb')='create' and json_extract_string(m,'$.objectRef.resource')='pods'
   and json_extract_string(m,'$.objectRef.subresource') is null
   and json_extract_string(m,'$.requestObject.spec.containers[0].securityContext.privileged')='true'"""
q = {
    "eks": native.format(t="eks"),
    "gke": """select operation.id id, protoPayload.authenticationInfo.principalEmail who from gke
 where protoPayload.methodName='io.k8s.core.v1.pods.create'
   and json_extract_string(to_json(protoPayload.request),'$.spec.containers[0].securityContext.privileged')='true'""",
    "aks": native.format(t="aks"),
}
for c, s in q.items():
    print(c, con.sql(f"select count(*) hits, count(g.auditID) true_pos, string_agg(distinct who, ' | ') who from ({s}) x left join gt g on g.auditID=x.id and g.cloud='{c}'").fetchall())
print("gke gt join:", con.sql("select count(*) from gke where operation.id::varchar in (select auditID from gt where cloud='gke')").fetchone())
print("aks gt join:", con.sql("select count(*) from aks where json_extract_string(m,'$.auditID') in (select auditID from gt where cloud='aks')").fetchone())
