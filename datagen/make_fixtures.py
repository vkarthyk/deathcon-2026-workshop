"""Build the Lab 4 enrichment fixtures (identity, service accounts, assets, IP reputation).

Derived from the same cloud profiles as the logs, so principals and IPs always line up.
Join keys use OCSF values (cloud.provider, actor.user.name, src_endpoint.ip), not cloud-native names.
"""

import csv
import json
import os
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_k8s as k  # noqa: E402

OUT = Path(os.environ.get("WORKSHOP_DATA", Path(__file__).resolve().parent.parent / "data")) / "fixtures"
PROVIDER = {"eks": "AWS", "gke": "GCP", "aks": "Azure"}
IN_CLUSTER = {"eks": ("10.0.0.0/16", "10.0."), "gke": ("10.128.0.0/20", "10.128."),
              "aks": ("10.224.0.0/16", "10.224.")}
# Built-in controllers call from the control plane, which on GKE sits outside the node range.
CONTROL_PLANE = {"eks": ("10.0.0.0/24", "10.0.0."), "gke": ("172.16.0.0/28", "172.16.0."),
                 "aks": ("10.224.0.0/24", "10.224.0.")}


def write(name, header, rows):
    OUT.mkdir(parents=True, exist_ok=True)
    with open(OUT / f"{name}.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)
    print(f"{name}.csv: {len(rows)} rows")


DEPARTMENT = {"developer": "Payments Engineering", "sre": "Site Reliability"}
TITLE = {"developer": ["Software Engineer", "Senior Software Engineer"], "sre": ["SRE", "Senior SRE", "Staff SRE"]}
MANAGER = {"developer": "mlee@example.com", "sre": "kchen@example.com"}


def main():
    manifest = json.loads((OUT.parent / "raw" / "manifest.json").read_text())
    scale = manifest["scale"]
    profiles = k.make_profiles(scale)
    staff = profiles["eks"]["staff"]
    prng = random.Random(f"{k.SEED}-fixtures")

    # People. jdoe is on PTO and only ever uses a Mac: both contradict the attack telemetry.
    write("identities",
          ["person_id", "display_name", "email", "department", "title", "manager_email",
           "employment_status", "usual_client_os", "home_country", "out_of_office"],
          [(p["person_id"], p["name"], p["email"], DEPARTMENT[p["role"]],
            "Staff SRE" if p["key"] == "rpatel" else
            "Software Engineer" if p["key"] == "jdoe" else prng.choice(TITLE[p["role"]]),
            MANAGER[p["role"]], "active", p["os"], "US", p["out_of_office"]) for p in staff])

    # Every native principal a person (or the CI pipeline) shows up as, per cloud.
    links = []
    for cloud, prof in profiles.items():
        for who, person in [(p["key"], p["person_id"]) for p in staff] + [("ci", "CI-GITHUB")]:
            u = prof["users"][who]
            uid = (u.get("extra", {}).get("oid") or [u.get("uid")])[0] if cloud != "gke" else None
            links.append((person, PROVIDER[cloud], u["username"], uid,
                          "workload_identity" if who == "ci" else "human"))
    write("identity_links", ["person_id", "cloud_provider", "principal_name", "principal_uid", "principal_kind"],
          links)

    # Kubernetes service accounts: who owns them, how privileged, where they should run from.
    sas = []
    for cloud in profiles:
        cidr, prefix = IN_CLUSTER[cloud]
        sas += [
            (PROVIDER[cloud], "system:serviceaccount:argocd:argocd-application-controller", "Platform",
             "cluster-admin", cidr, prefix, "GitOps controller; runs in-cluster only"),
            (PROVIDER[cloud], "system:serviceaccount:external-secrets:external-secrets", "Platform",
             "namespaced secrets read/write", cidr, prefix, "Syncs secrets from cloud secret manager"),
            (PROVIDER[cloud], "system:serviceaccount:kube-system:daemon-set-controller", "Cloud provider",
             "controller", *CONTROL_PLANE[cloud], "Built-in DaemonSet controller"),
            (PROVIDER[cloud], "system:serviceaccount:cert-manager:cert-manager", "Platform",
             "namespaced secrets read/write", cidr, prefix, "Issues and renews TLS certificates"),
            (PROVIDER[cloud], "system:serviceaccount:monitoring:prometheus", "Observability",
             "cluster-wide read", cidr, prefix, "Metrics scraping and service discovery"),
            (PROVIDER[cloud], "system:serviceaccount:kube-system:coredns", "Cloud provider",
             "cluster-wide read", cidr, prefix, "Cluster DNS"),
            (PROVIDER[cloud], "system:serviceaccount:kube-system:cluster-autoscaler", "Platform",
             "node and pod management", cidr, prefix, "Scales node pools"),
        ]
    write("service_accounts",
          ["cloud_provider", "principal_name", "owner_team", "privilege", "in_cluster_cidr",
           "in_cluster_ip_prefix", "description"], sas)

    write("clusters",
          ["cloud_provider", "account_uid", "cluster_name", "region", "environment",
           "data_classification", "owner_team", "node_cidr"],
          [(PROVIDER[c], p["account"], k.CLUSTER, p["region"], "prod", "PCI", "Payments Platform",
            IN_CLUSTER[c][0]) for c, p in profiles.items()])

    # Known-good privileged workloads: the platform's own CNI/proxy/CSI DaemonSets.
    allow = []
    for cloud, prof in profiles.items():
        for ds, image in prof["system_daemonsets"]:
            allow.append((PROVIDER[cloud], "kube-system", "DaemonSet", ds, image.rsplit(":", 1)[0],
                          "Managed by cloud provider; privileged by design"))
    write("privileged_allowlist",
          ["cloud_provider", "namespace", "owner_kind", "owner_name", "image_prefix", "justification"], allow)

    write("approved_registries", ["registry_prefix", "description"], [
        ("602401143452.dkr.ecr.", "Amazon EKS add-on images"),
        ("gke.gcr.io/", "GKE system images"),
        ("mcr.microsoft.com/", "Microsoft Container Registry"),
        ("docker.io/library/", "Docker official images"),
        ("ghcr.io/acme/", "Acme internal images"),
    ])

    # ASNs are from the RFC 5398 documentation ranges; addresses from RFC 5737 / RFC 2544 test ranges.
    # Sized like a real feed slice, so an agent can't just read the whole table.
    named = [
        *[(ip, "corp_egress", "benign", 64496, "ACME-CORP", "US", "vpn;office", "internal", "2026-10-14")
          for ip in k.CORP_EGRESS],
        (k.CI_EGRESS, "ci", "benign", 64497, "ACME-CI-NAT", "US", "github_actions", "internal", "2026-10-14"),
        *[(ip, "scanner", "suspicious", 64510, "SCANCO-RESEARCH", "DE", "mass_scanner;benign_research",
           "threatfeed-a", "2026-10-14") for ip in k.scanner_ips(scale)],
        (k.ATTACKER_IP, "vps_hosting", "malicious", 64511, "NIGHTOWL-HOSTING", "NL",
         "bulletproof_hosting;open_docker_registry:5000;k8s_api_bruteforce", "threatfeed-a;threatfeed-b",
         "2026-10-13"),
    ]
    kinds = [  # category, reputation, as_org, asn, countries, tags, weight
        ("residential", "benign", "HOMENET-ISP", 65536, ["US", "GB", "DE", "IN", "BR"], "residential", 30),
        ("cloud_hosting", "unknown", "BIGCLOUD-COMPUTE", 65537, ["US", "IE", "SG"], "cloud", 25),
        ("vps_hosting", "suspicious", "CHEAPVPS-LLC", 65538, ["NL", "RU", "US", "RO"], "vps", 15),
        ("vps_hosting", "malicious", "NIGHTOWL-HOSTING", 64511, ["NL"], "bulletproof_hosting", 3),
        ("scanner", "suspicious", "SCANCO-RESEARCH", 64510, ["DE", "US"], "mass_scanner", 10),
        ("tor_exit", "suspicious", "TOR-EXIT", 65539, ["DE", "NL", "FR", "SE"], "tor_exit", 7),
        ("botnet", "malicious", "VARIOUS", 65540, ["CN", "RU", "BR", "VN"], "botnet_c2;credential_stuffing", 10),
    ]
    taken = {r[0] for r in named}
    bulk = []
    while len(bulk) < 4000:
        ip = f"198.{prng.randint(18, 19)}.{prng.randint(0, 255)}.{prng.randint(1, 254)}"
        if ip in taken:
            continue
        taken.add(ip)
        cat, rep, org, asn, countries, tags, _ = prng.choices(kinds, [kd[-1] for kd in kinds])[0]
        bulk.append((ip, cat, rep, asn, org, prng.choice(countries), tags,
                     prng.choice(["threatfeed-a", "threatfeed-b", "threatfeed-a;threatfeed-b"]),
                     f"2026-{prng.randint(7, 10):02d}-{prng.randint(1, 28):02d}"))
    write("ip_reputation", ["ip", "category", "reputation", "asn", "as_org", "country", "tags", "source", "last_seen"],
          sorted(named + bulk))


if __name__ == "__main__":
    main()
