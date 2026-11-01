"""Small deterministic behavioral corpus; no upstream download or model credentials.

Produces modeled cloud envelopes, inventory, case labels and enterprise-style enrichment.
Labels never enter the detection input or agent tools. Run with --check for byte stability.
"""

import argparse
import copy
import csv
import gzip
import io
import ipaddress
import json
from pathlib import Path
import random
import sys
import uuid
from datetime import timedelta

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from datagen import build_k8s as k  # noqa: E402

OUT = ROOT / "data" / "behavioral"
SCENARIOS = (
    "compromise", "approved_maintenance", "wrong_subject", "wrong_cluster", "reversed",
    "outside_window", "denied_grant", "duplicate_stage", "missing_reads", "unresolved_identity",
    "single_cloud", "shared_nat", "expired_approval", "second_subject", "missing_request",
)


def csv_bytes(rows, fields):
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue().encode()


IP_FIELDS = [
    "ip_address", "ip_version", "asn", "asn_org", "bogon_or_private",
    "country_code", "city", "region", "reputation_score", "threat_category", "is_malicious",
    "is_vpn", "is_proxy", "is_tor", "is_hosting", "is_cloud", "network_type", "reputation", "source",
]


def ip_context(address, index, network_type=None):
    """Invented enterprise enrichment, not a live lookup of documentation IP ranges."""
    parsed = ipaddress.ip_address(address)
    network_type = network_type or ("corporate_vpn" if index % 3 == 1 else "external")
    internal = network_type == "private"
    malicious = not internal and index % 5 == 0
    tor = not internal and index % 7 == 2
    hosting = not internal and network_type != "corporate_vpn"
    country, city, region = (("US", "San Francisco", "California"), ("DE", "Frankfurt", "Hesse"),
                            ("SG", "Singapore", "Singapore"))[index % 3]
    return dict(
        ip_address=str(parsed), ip_version=f"IPv{parsed.version}",
        asn=None if internal else f"AS{64512 + index % 3}",
        asn_org="Example Internal Network" if internal else "Example Cloud Hosting" if hosting else "Example Corporate Network",
        bogon_or_private=not parsed.is_global,
        country_code=None if internal else country, city=None if internal else city, region=None if internal else region,
        reputation_score=0 if internal else 85 + index % 16 if malicious else 10 + index % 6 * 10,
        threat_category="C2" if malicious else "Tor Exit Node" if tor else "No Known Threat",
        is_malicious=malicious, is_vpn=not internal and (network_type == "corporate_vpn" or index % 4 == 1),
        is_proxy=not internal and index % 6 == 2, is_tor=tor, is_hosting=hosting,
        is_cloud=hosting and index % 2 == 0, network_type=network_type,
        reputation="malicious" if malicious else "unknown",
        source="synthetic network inventory / threat intelligence; ASN and location are fictional",
    )


def _build(split):
    seed = 815 if split == "training" else 1029
    k.rng = random.Random(seed)
    profiles = k.make_profiles(1)
    artifacts, records = {}, {cloud: [] for cloud in profiles}
    identities, approvals, labels, cases = [], [], [], []
    ip_enrichment, user_enrichment, cluster_enrichment = {}, [], []
    scenarios = SCENARIOS + (("boundary_inclusive", "boundary_exceeded", "namespaced_read", "other_account")
                             if split == "holdout" else ())
    for index, scenario in enumerate(scenarios):
        case = f"{split}-{index:02d}"
        cluster = f"workload-{index + (10 if split == 'training' else 70)}"
        k.CLUSTER = cluster
        person = f"person-{seed}-{index}"
        email = f"analyst{seed + index}@example.com"
        oid = str(uuid.uuid5(uuid.NAMESPACE_URL, email))
        start = k.DAY + timedelta(days=1 if split == "training" else 2, hours=index)
        cloud_count = 1 if scenario == "single_cloud" else 3
        grant_ids, required_ids = [], []
        for cloud_index, (cloud, profile) in enumerate(profiles.items()):
            if cloud_index >= cloud_count:
                continue
            prof = copy.deepcopy(profile)
            human = {"eks": lambda: k.eks_iam(prof['account'], 'developer', email, 'AROAexampleBEHAVIOR'),
                     "gke": lambda: k.gke_google(email),
                     "aks": lambda: k.aks_entra(email, oid, [])}[cloud]()
            other = dict(human, username=f"other{index}@example.com")
            controller = k.sa_user("ops", "release-controller")
            provider = {"eks": "AWS", "gke": "GCP", "aks": "Azure"}[cloud]
            ts = start + timedelta(minutes=cloud_index * 7)
            ip = "203.0.113.10" if scenario == "approved_maintenance" else f"198.51.100.{30 + index}"
            # The RBAC actor is deliberately not the grant's subject.
            body = {"kind": "ClusterRoleBinding", "apiVersion": "rbac.authorization.k8s.io/v1",
                    "metadata": {"name": f"access-{index}"},
                    "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "cluster-admin"},
                    "subjects": [{"kind": "User", "name": human["username"], "apiGroup": "rbac.authorization.k8s.io"}]}
            if scenario == "second_subject":
                body["subjects"].insert(0, {"kind": "User", "name": other["username"]})
            grant = k.simple(prof, ts, controller, ip, k.KUBECTL_LINUX, "create", "clusterrolebindings",
                             group="rbac.authorization.k8s.io", name=f"access-{index}",
                             code=403 if scenario == "denied_grant" else 201,
                             extra={"requestObject": body})
            secret_time = ts + timedelta(minutes=24 if scenario == "outside_window" else 4)
            if scenario in ("boundary_inclusive", "boundary_exceeded"):
                secret_time = ts + timedelta(minutes=15, seconds=int(scenario == "boundary_exceeded"))
            if scenario == "reversed":
                secret_time = ts - timedelta(minutes=1)
            reader = other if scenario in ("wrong_subject", "shared_nat") else human
            secret = k.simple(prof, secret_time, reader, ip, k.KUBECTL_LINUX, "list", "secrets",
                              ns="payments" if scenario == "namespaced_read" else None)
            grant_ids.append(grant["auditID"])
            events = [grant]
            if scenario != "missing_reads":
                events.append(secret)
            if scenario == "missing_request":
                grant.pop("requestObject", None)
            if scenario == "duplicate_stage":
                duplicate = copy.deepcopy(secret)
                duplicate["stage"] = "ResponseStarted"
                events += [duplicate, copy.deepcopy(grant)]
            if scenario == "wrong_cluster":
                # Emit the read using another cluster envelope, not another identity.
                events.remove(secret)
                k.CLUSTER = cluster + "-other"
                records[cloud].extend(k.ENVELOPES[cloud](prof, [secret]))
                k.CLUSTER = cluster
            if scenario == "other_account":
                events.remove(secret)
                alternate = dict(prof, account={"eks": "999900001111", "gke": "other-project",
                                              "aks": "00000000-0000-4000-8000-000000000099"}[cloud])
                records[cloud].extend(k.ENVELOPES[cloud](alternate, [secret]))
            records[cloud].extend(k.ENVELOPES[cloud](prof, events))
            if scenario != "unresolved_identity":
                identities.append(dict(person_id=person, cloud_provider=provider, account_uid=prof["account"],
                                       principal_name=human["username"], email=email))
            # Synthetic enterprise inventories, independent of detection/evaluation labels.
            if scenario != "duplicate_stage":  # Missing inventory demonstrates neutral severity.
                ip_enrichment[ip] = ip_context(ip, index)
                user_enrichment.append(dict(cloud_provider=provider, account_uid=prof["account"],
                                            principal_name=human["username"], department="platform",
                                            employment_status="inactive" if index % 4 == 0 else "active",
                                            is_privileged_admin=index % 3 == 1, source="IdP / PAM inventory"))
                cluster_enrichment.append(dict(cloud_provider=provider, account_uid=prof["account"],
                                               cluster_name=cluster, environment="development" if index % 3 == 1 else "production",
                                               data_sensitivity="restricted" if index % 3 == 0 else "internal",
                                               owner_team="platform-security", source="CMDB / Kubernetes inventory"))
            if scenario in ("approved_maintenance", "expired_approval"):
                approvals.append(dict(cloud_provider=provider, account_uid=prof["account"], cluster_name=cluster,
                                      grant_actor=controller["username"], subject=human["username"],
                                      role="cluster-admin", start_time=k.iso(ts - timedelta(minutes=5)),
                                      end_time=k.iso(ts + timedelta(minutes=10 if scenario == 'approved_maintenance' else -1)),
                                      ticket=f"CHG-{seed}-{index}"))
            matches = scenario in ("compromise", "approved_maintenance", "duplicate_stage", "unresolved_identity",
                                   "single_cloud", "expired_approval", "second_subject", "boundary_inclusive")
            malicious = (matches or scenario in ("missing_reads", "missing_request")) and scenario != "approved_maintenance"
            disposition = ("inconclusive" if scenario in ("missing_reads", "missing_request", "wrong_subject", "wrong_cluster",
                           "reversed", "outside_window", "shared_nat", "boundary_exceeded", "namespaced_read", "other_account")
                           else "suspicious" if scenario == "unresolved_identity"
                           else "malicious" if malicious else "benign")
            evidence = [grant["auditID"], secret["auditID"]] if matches else [grant["auditID"]]
            required_ids.extend(evidence)
            labels.append(dict(case_id=case, alert_key=grant["auditID"], provider=provider,
                               expected_match=matches, malicious=malicious,
                               observable=scenario not in ("missing_reads", "missing_request"),
                               expected_disposition=disposition, required_evidence=json.dumps(evidence)))
        cases.append(dict(case_id=case, scenario=scenario, cluster_name=cluster,
                          alert_event_ids=grant_ids, evidence_ids=required_ids,
                          split=split, description="Controlled fixture; see scenario specification."))
    # Context-only examples exercise IPv6 and internal/loopback inventory without changing events.
    for address, index, network_type in (("2001:db8::1", 17, "external"), ("10.0.0.10", 18, "private"),
                                          ("::1", 19, "private")):
        ip_enrichment[address] = ip_context(address, index, network_type)
    for cloud, rows in records.items():
        content = "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows).encode()
        artifacts[f"{cloud}/{cloud}_audit.jsonl.gz"] = gzip.compress(content, mtime=0)
    for name, rows, fields in (
        ("identities", identities, ["person_id", "cloud_provider", "account_uid", "principal_name", "email"]),
        ("ip_enrichment", list(ip_enrichment.values()), IP_FIELDS),
        ("user_enrichment", user_enrichment, ["cloud_provider", "account_uid", "principal_name", "department", "employment_status", "is_privileged_admin", "source"]),
        ("k8s_cluster_enrichment", cluster_enrichment, ["cloud_provider", "account_uid", "cluster_name", "environment", "data_sensitivity", "owner_team", "source"]),
        ("approvals", approvals, ["cloud_provider", "account_uid", "cluster_name", "grant_actor", "subject", "role", "start_time", "end_time", "ticket"]),
        ("labels", labels, ["case_id", "alert_key", "provider", "expected_match", "malicious", "observable", "expected_disposition", "required_evidence"]),
    ):
        artifacts[f"{name}.csv"] = csv_bytes(rows, fields)
    artifacts["cases.json"] = (json.dumps(cases, indent=2) + "\n").encode()
    return artifacts


def build(split):
    original_cluster, original_rng = k.CLUSTER, k.rng
    try:
        return _build(split)
    finally:
        k.CLUSTER, k.rng = original_cluster, original_rng


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    original_cluster = k.CLUSTER
    try:
        for split in ("training", "holdout"):
            for name, content in build(split).items():
                path = OUT / split / name
                if args.check:
                    if not path.exists() or path.read_bytes() != content:
                        raise SystemExit(f"Corpus differs: {path}; regenerate deliberately")
                else:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(content)
        print("Behavioral corpus verified" if args.check else "Behavioral corpus generated")
    finally:
        k.CLUSTER = original_cluster


if __name__ == "__main__":
    main()
