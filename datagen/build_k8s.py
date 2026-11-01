"""Build the synthetic EKS / GKE / AKS audit datasets for the workshop.

Seeds attack events from splunk/attack_data (Apache-2.0), re-identifies them onto a
fictional payments-prod cluster in each cloud, stitches them into one privilege-
escalation chain (same leaked developer, same attacker IP, staggered across clouds),
mixes in benign traffic with FP traps, and emits each cloud's native delivery format:

  eks: CloudWatch Logs subscription records; audit event is a JSON string in logEvents[].message
  gke: Cloud Logging LogEntry (GCS sink); audit event re-shaped into protoPayload AuditLog
  aks: Azure diagnostic records (Event Hub capture); audit event is a JSON string in properties.log

Usage:
    python3.11 -I datagen/build_k8s.py --attack-data vendor/attack_data --out data/raw [--scale 25]
"""

import argparse
import copy
import csv
import gzip
import hashlib
import json
import random
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

SEED = 1994
DAY = datetime(2026, 10, 14, tzinfo=timezone.utc)
CLUSTER = "payments-prod"

# RFC 5737 ranges only; real addresses from the seed data must never survive.
CORP_EGRESS = [f"203.0.113.{i}" for i in range(10, 30)]  # office + VPN pool
CI_EGRESS = "192.0.2.50"
ATTACKER_IP = "198.51.100.23"

SEEDS = {
    "privileged_pod": "T1204/kubernetes_privileged_pod/kubernetes_privileged_pod.json",
    "get_secret": "T1552.007/kube_audit_get_secret/kube_audit_get_secret.json",
    "forbidden": "T1204/kubernetes_unauthorized_access/kubernetes_unauthorized_access.json",
    "daemonset": "T1204/kubernetes_audit_daemonset_created/kubernetes_audit_daemonset_created.json",
    "cronjob": "T1053.007/kubernetes_audit_cron_job_creation/kubernetes_audit_cron_job_creation.json",
    "nodeport": "T1204/kube_audit_create_node_port_service/kube_audit_create_node_port_service.json",
    "kubelet_event": "T1526/kubernetes_audit_pull_image/kubernetes_audit_pull_image.json",
    "scan": "T1046/kubernetes_scanning/kubernetes_scanning.json",
}

TS_RE = re.compile(r"20\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z")
KUBECTL_MAC = "kubectl/v1.30.4 (darwin/arm64) kubernetes/a51b3b7"
KUBECTL_LINUX = "kubectl/v1.30.2 (linux/amd64) kubernetes/3968350"
rng = random.Random(SEED)


def new_uuid():
    return str(uuid.UUID(int=rng.getrandbits(128)))


def iso(ts):
    return ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_iso(s):
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Identities and per-cloud system components
# ---------------------------------------------------------------------------

def sa_user(ns, name):
    return {
        "username": f"system:serviceaccount:{ns}:{name}",
        "uid": new_uuid(),
        "groups": ["system:serviceaccounts", f"system:serviceaccounts:{ns}", "system:authenticated"],
        "extra": {"authentication.kubernetes.io/pod-name": [f"{name}-0"]},
    }


def system_user(name, groups=("system:authenticated",)):
    return {"username": name, "groups": list(groups)}


def eks_iam(account, role, session, principal_id):
    """EKS access entry: username is the assumed-role ARN; IAM detail lives in user.extra."""
    arn = f"arn:aws:sts::{account}:assumed-role/{role}/{session}"
    return {
        "username": arn,
        "uid": f"aws-iam-authenticator:{account}:{principal_id}",
        "groups": ["system:authenticated"],
        "extra": {
            # principal_id starts "AROAexample": the lowercase keeps these fake IDs off AWS-key scanners.
            "accessKeyId": [f"ASIA{principal_id[4:12]}EXAMPLE"],
            "arn": [arn],
            "canonicalArn": [f"arn:aws:iam::{account}:role/{role}"],
            "principalId": [principal_id],
            "sessionName": [session],
            "sigs.k8s.io/aws-iam-authenticator/principalId": [principal_id],
        },
    }


def gke_google(email):
    """GKE Google identity; GKE audit logs keep only principalEmail, so groups are moot."""
    return {"username": email, "groups": ["system:authenticated"]}


def aks_entra(upn, oid, group_oids):
    """AKS Entra ID: groups are Entra object IDs; service principals have no UPN, only an oid."""
    return {"username": upn or oid, "groups": group_oids + ["system:authenticated"], "extra": {"oid": [oid]}}


FIRST = ["Avery", "Blake", "Casey", "Dana", "Eli", "Farah", "Gabe", "Hana", "Ivan", "Jules", "Kai", "Lena",
         "Milo", "Nia", "Omar", "Priya", "Quinn", "Rosa", "Sami", "Tara", "Umar", "Vera", "Wes", "Xena",
         "Yuki", "Zane", "Ana", "Ben", "Cleo", "Dev"]
LAST = ["Abara", "Brooks", "Chen", "Diaz", "Evans", "Fischer", "Garcia", "Haddad", "Ito", "Jensen", "Kowalski",
        "Lopez", "Moreau", "Nakamura", "Okafor", "Petrov", "Quaid", "Rossi", "Singh", "Tanaka"]
NAMESPACES = ["payments", "checkout", "ledger", "fraud-scoring", "notifications", "risk", "merchant-api", "billing"]


def staff_roster(scale):
    """Engineers with deterministic identities; the first three are the story's named characters."""
    prng = random.Random(f"{SEED}-staff")
    core = [
        dict(key="jdoe", person_id="P-1001", name="Jordan Doe", email="jdoe@example.com", role="developer",
             namespaces=["payments"], os="darwin", out_of_office="PTO 2026-10-12..2026-10-19"),
        dict(key="asmith", person_id="P-1002", name="Alex Smith", email="asmith@example.com", role="developer",
             namespaces=["payments", "checkout"], os="darwin", out_of_office=""),
        dict(key="rpatel", person_id="P-1003", name="Riya Patel", email="rpatel@example.com", role="sre",
             namespaces=NAMESPACES, os="darwin", out_of_office=""),
    ]
    names = prng.sample([(f, l) for f in FIRST for l in LAST], int(2 * scale))
    extra = []
    for i, (first, last) in enumerate(names):
        role = "sre" if prng.random() < 0.2 else "developer"
        ooo = "PTO 2026-10-13..2026-10-16" if prng.random() < 0.08 else ""
        extra.append(dict(
            key=f"u{i:03d}", person_id=f"P-{1100 + i}", name=f"{first} {last}",
            email=f"{first.lower()}.{last.lower()}@example.com", role=role,
            namespaces=NAMESPACES if role == "sre" else prng.sample(NAMESPACES, prng.randint(1, 2)),
            os=prng.choices(["darwin", "linux", "windows"], [0.8, 0.15, 0.05])[0], out_of_office=ooo))
    for p in core + extra:
        p["principal_id"] = "AROAexample" + hashlib.sha256(p["email"].encode()).hexdigest()[:9].upper()
        p["entra_oid"] = str(uuid.UUID(hashlib.sha256(p["email"].encode()).hexdigest()[:32]))
    return core + extra


def node_ips(cloud, n):
    prng = random.Random(f"{SEED}-{cloud}-nodes")
    base = {"eks": "10.0.{}.{}", "gke": "10.128.{}.{}", "aks": "10.224.{}.{}"}[cloud]
    third = {"eks": (12, 15), "gke": (0, 3), "aks": (0, 3)}[cloud]
    ips = set()
    while len(ips) < n:
        ips.add(base.format(prng.randint(*third), prng.randint(5, 250)))
    return sorted(ips)


def scanner_ips(scale):
    """Internet scanners from the RFC 2544 benchmarking range (198.18.0.0/15): never routable."""
    prng = random.Random(f"{SEED}-scanners")
    return sorted({f"198.{prng.randint(18, 19)}.{prng.randint(0, 255)}.{prng.randint(1, 254)}"
                   for _ in range(max(3, int(2 * scale)))})


def make_profiles(scale=1):
    aws_account = "111122223333"
    gcp_project = "acme-payments-prod"
    azure_sub = "00000000-1111-4222-8333-444444444444"
    entra_groups = {"developer": "6f1e3b2a-0000-4000-8000-00000000d0e5", "sre": "6f1e3b2a-0000-4000-8000-0000000005e0"}
    staff = staff_roster(scale)
    n_nodes = 5 + int(2 * scale)
    shared = {
        "argocd": sa_user("argocd", "argocd-application-controller"),
        "external_secrets": sa_user("external-secrets", "external-secrets"),
        "cert_manager": sa_user("cert-manager", "cert-manager"),
        "prometheus": sa_user("monitoring", "prometheus"),
        "coredns": sa_user("kube-system", "coredns"),
        "autoscaler": sa_user("kube-system", "cluster-autoscaler"),
        "kcm": system_user("system:kube-controller-manager"),
        "scheduler": system_user("system:kube-scheduler"),
        "ds_controller": sa_user("kube-system", "daemon-set-controller"),
        "anonymous": system_user("system:anonymous", ("system:unauthenticated",)),
    }
    idents = {
        "eks": lambda p: eks_iam(aws_account, f"eks-{p['role']}", p["email"], p["principal_id"]),
        "gke": lambda p: gke_google(p["email"]),
        "aks": lambda p: aks_entra(p["email"], p["entra_oid"], [entra_groups[p["role"]]]),
    }
    ci = {
        "eks": eks_iam(aws_account, "github-actions-deployer", "GitHubActions", "AROAexampleCIDEPLOY1"),
        "gke": gke_google(f"github-deployer@{gcp_project}.iam.gserviceaccount.com"),
        "aks": aks_entra(None, "9d4e7a10-0000-4000-8000-0000000c1d3b", []),
    }
    base = {
        "eks": {
            "attack_start": DAY.replace(hour=14, minute=2, second=11),
            "account": aws_account, "region": "us-west-2", "control_plane_ip": "10.0.0.10",
            "nodes": [(ip, f"ip-{ip.replace('.', '-')}.us-west-2.compute.internal") for ip in node_ips("eks", n_nodes)],
            "kubelet_ua": "kubelet/v1.30.4-eks-a737599 (linux/amd64) kubernetes/a51b3b7",
            "addon_manager": system_user("eks:addon-manager"),
            "system_daemonsets": [
                ("aws-node", "602401143452.dkr.ecr.us-west-2.amazonaws.com/amazon-k8s-cni:v1.18.3"),
                ("kube-proxy", "602401143452.dkr.ecr.us-west-2.amazonaws.com/eks/kube-proxy:v1.30.3"),
            ],
            "addon_crbs": ["eks:addon-cluster-admin", "eks:podsecuritypolicy:authenticated"],
            "in_cluster_extra_ip": False,
        },
        "gke": {
            "attack_start": DAY.replace(hour=14, minute=38, second=47),
            "account": gcp_project, "region": "us-central1", "control_plane_ip": "172.16.0.2",
            "nodes": [(ip, f"gke-{CLUSTER}-default-pool-3f9a1c2e-{hashlib.sha256(ip.encode()).hexdigest()[:4]}")
                      for ip in node_ips("gke", n_nodes)],
            "kubelet_ua": "kubelet/v1.30.5-gke.1014001 (linux/amd64) kubernetes/8b3d6c1",
            "addon_manager": system_user("system:addon-manager"),
            "system_daemonsets": [
                ("netd", "gke.gcr.io/netd:v0.7.8-gke.6"),
                ("pdcsi-node", "gke.gcr.io/gcp-compute-persistent-disk-csi-driver:v1.13.4-gke.0"),
            ],
            "addon_crbs": ["system:managed-certificate-controller", "gce:podsecuritypolicy:calico-sa"],
            "in_cluster_extra_ip": False,
        },
        "aks": {
            "attack_start": DAY.replace(hour=15, minute=11, second=5),
            "account": azure_sub, "region": "westus2", "resource_group": "rg-payments-prod",
            "control_plane_ip": "10.224.0.4",
            "nodes": [(ip, f"aks-nodepool1-28471932-vmss{n:06x}") for n, ip in enumerate(node_ips("aks", n_nodes))],
            "kubelet_ua": "kubelet/v1.30.6 (linux/amd64) kubernetes/7a3e1b0",
            "addon_manager": system_user("aksService", ("system:masters", "system:authenticated")),
            "system_daemonsets": [
                ("azure-cns", "mcr.microsoft.com/containernetworking/azure-cns:v1.6.13"),
                ("kube-proxy", "mcr.microsoft.com/oss/kubernetes/kube-proxy:v1.30.6-hotfix.20241015"),
            ],
            "addon_crbs": ["aks-service-rolebinding", "system:azure-cloud-provider"],
            # AKS konnectivity: in-cluster callers show [pod/node IP, tunnel IP].
            "in_cluster_extra_ip": True,
        },
    }
    for cloud, prof in base.items():
        prof["cloud"] = cloud
        prof["staff"] = staff
        prof["scale"] = scale
        prof["users"] = {**copy.deepcopy(shared), "ci": ci[cloud], "addon_manager": prof.pop("addon_manager"),
                         **{p["key"]: idents[cloud](p) for p in staff}}
    return base


# ---------------------------------------------------------------------------
# Canonical audit.k8s.io/v1 events (cloud-agnostic, rewrapped later)
# ---------------------------------------------------------------------------

def load_seeds(root):
    base = Path(root) / "datasets" / "attack_techniques"
    out = {}
    for key, rel in SEEDS.items():
        lines = [json.loads(l) for l in (base / rel).read_text().splitlines() if l.strip()]
        out[key] = lines if key == "scan" else lines[0]
    return out


def source_ips(prof, ip):
    if prof["in_cluster_extra_ip"] and ip.startswith("10."):
        return [ip, prof["control_plane_ip"]]
    return [ip]


def finalize(prof, ev, ts, user, ip, ua, renames=None):
    """Re-identify a seed event: new time, auditID, actor, source; optional name substitutions."""
    raw = json.dumps(ev)
    for old, new in (renames or {}).items():
        raw = raw.replace(old, new)
    raw = TS_RE.sub(ts.strftime("%Y-%m-%dT%H:%M:%SZ"), raw)
    ev = json.loads(raw)
    ev["auditID"] = new_uuid()
    ev["user"] = copy.deepcopy(user)
    ev["sourceIPs"] = source_ips(prof, ip)
    ev["userAgent"] = ua
    ev["requestReceivedTimestamp"] = iso(ts)
    ev["stageTimestamp"] = iso(ts + timedelta(milliseconds=rng.randint(3, 60)))
    meta = (ev.get("responseObject") or {}).get("metadata") or {}
    if "uid" in meta:
        meta["uid"] = new_uuid()
    if "resourceVersion" in meta:
        meta["resourceVersion"] = str(rng.randint(40_000_000, 49_999_999))
    return ev


def simple(prof, ts, user, ip, ua, verb, resource, ns=None, name=None, code=200, group="",
           subresource=None, uri=None, decision="allow", reason="", level="Metadata", extra=None):
    """Hand-built event for verbs the seed data doesn't cover."""
    obj = {"resource": resource, "apiVersion": "v1"}
    if group:
        obj["apiGroup"] = group
    if ns:
        obj["namespace"] = ns
    if name:
        obj["name"] = name
    if subresource:
        obj["subresource"] = subresource
    prefix = f"/apis/{group}/v1" if group else "/api/v1"
    if uri is None:
        uri = prefix + (f"/namespaces/{ns}" if ns else "") + f"/{resource}" + (f"/{name}" if name else "")
        if subresource:
            uri += f"/{subresource}"
    status = {"metadata": {}, "code": code}
    if code == 403:
        status.update(status="Failure", reason="Forbidden",
                      message=f'{resource} is forbidden: User "{user["username"]}" cannot {verb} resource '
                              f'"{resource}" in API group "{group}"' + (f' in the namespace "{ns}"' if ns else " at the cluster scope"))
        decision = "forbid"
    ev = {
        "kind": "Event", "apiVersion": "audit.k8s.io/v1", "level": level,
        "auditID": new_uuid(), "stage": "ResponseComplete",
        "requestURI": uri, "verb": verb, "user": copy.deepcopy(user), "sourceIPs": source_ips(prof, ip),
        "userAgent": ua, "objectRef": obj, "responseStatus": status,
        "requestReceivedTimestamp": iso(ts),
        "stageTimestamp": iso(ts + timedelta(milliseconds=rng.randint(2, 40))),
        "annotations": {"authorization.k8s.io/decision": decision, "authorization.k8s.io/reason": reason},
    }
    if extra:
        ev.update(extra)
    return ev


def privileged_pod_spec(name, ns, image):
    return {"kind": "Pod", "apiVersion": "v1", "metadata": {"name": name, "namespace": ns},
            "spec": {"containers": [{"name": name, "image": image, "securityContext": {"privileged": True}}],
                     "hostNetwork": True, "hostPID": True}}


def build_attack(prof, seeds):
    """The chain; returns [(event, step, technique, description)]."""
    U = prof["users"]
    jdoe, sa = U["jdoe"], U["argocd"]
    pod, ns = "debug-tools-7f9c", "payments"
    t = prof["attack_start"]
    out = []

    def at(minutes, seconds=0):
        return t + timedelta(minutes=minutes, seconds=seconds)

    out.append((simple(prof, at(0), jdoe, ATTACKER_IP, KUBECTL_LINUX, "create", "selfsubjectrulesreviews",
                       group="authorization.k8s.io", code=201, uri="/apis/authorization.k8s.io/v1/selfsubjectrulesreviews"),
                1, "T1069", "Leaked jdoe creds used from new IP: kubectl auth can-i --list"))
    out.append((simple(prof, at(0, 40), jdoe, ATTACKER_IP, KUBECTL_LINUX, "list", "namespaces"),
                2, "T1613", "Enumerate namespaces"))
    out.append((simple(prof, at(1, 5), jdoe, ATTACKER_IP, KUBECTL_LINUX, "list", "secrets", ns="kube-system", code=403),
                3, "T1552.007", "Forbidden: list secrets in kube-system"))
    out.append((finalize(prof, seeds["forbidden"], at(1, 30), jdoe, ATTACKER_IP, KUBECTL_LINUX,
                         {"test2": "kube-system", "k8s-test-user": jdoe["username"]}),
                3, "T1610", "Forbidden: create job in kube-system"))
    out.append((simple(prof, at(2, 10), jdoe, ATTACKER_IP, KUBECTL_LINUX, "list", "secrets", ns=ns),
                4, "T1552.007", "List secrets in payments"))
    out.append((finalize(prof, seeds["get_secret"], at(2, 25), jdoe, ATTACKER_IP, KUBECTL_LINUX,
                         {"my-secret": "payments-db-credentials", '"default"': f'"{ns}"', "/default/": f"/{ns}/"}),
                4, "T1552.007", "Read payments-db-credentials"))

    priv = finalize(prof, seeds["privileged_pod"], at(5), jdoe, ATTACKER_IP, KUBECTL_LINUX,
                    {"privileged-the-pod": pod, '"default"': f'"{ns}"', "/default/": f"/{ns}/",
                     "nginx:latest": "docker.io/library/alpine:3.20"})
    # Seed pod lacks a hostPath mount; add one so the escape is visible in the request body.
    for body in (priv["requestObject"], priv.get("responseObject", {})):
        if "spec" in body:
            body["spec"]["volumes"] = [{"name": "host", "hostPath": {"path": "/", "type": ""}}]
            body["spec"]["containers"][0]["volumeMounts"] = [{"name": "host", "mountPath": "/host"}]
    out.append((priv, 5, "T1611", "Create privileged hostPID/hostNetwork pod with / hostPath"))

    nsenter = "&".join(f"command={c}" for c in
                       ["nsenter", "--target", "1", "--mount", "--uts", "--ipc", "--net", "--pid", "--", "bash"])
    out.append((simple(prof, at(6, 20), jdoe, ATTACKER_IP, KUBECTL_LINUX, "create", "pods", ns=ns, name=pod,
                       subresource="exec", code=101,
                       uri=f"/api/v1/namespaces/{ns}/pods/{pod}/exec?{nsenter}&container={pod}&stdin=true&stdout=true&tty=true"),
                6, "T1609", "kubectl exec nsenter into host PID 1"))

    # From here the attacker replays the argocd controller token lifted off the node.
    out.append((simple(prof, at(14), sa, ATTACKER_IP, KUBECTL_LINUX, "list", "clusterrolebindings",
                       group="rbac.authorization.k8s.io"),
                7, "T1528", "Stolen argocd SA token used from outside the cluster"))
    crb = {"kind": "ClusterRoleBinding", "apiVersion": "rbac.authorization.k8s.io/v1",
           "metadata": {"name": "jdoe-break-glass"},
           "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "cluster-admin"},
           "subjects": [{"apiGroup": "rbac.authorization.k8s.io", "kind": "User", "name": jdoe["username"]}]}
    out.append((simple(prof, at(14, 45), sa, ATTACKER_IP, KUBECTL_LINUX, "create", "clusterrolebindings",
                       group="rbac.authorization.k8s.io", name="jdoe-break-glass", code=201, level="RequestResponse",
                       uri="/apis/rbac.authorization.k8s.io/v1/clusterrolebindings?fieldManager=kubectl-create",
                       extra={"requestObject": crb, "responseObject": crb}),
                8, "T1098.006", "Bind jdoe to cluster-admin"))

    out.append((finalize(prof, seeds["daemonset"], at(18), jdoe, ATTACKER_IP, KUBECTL_LINUX,
                         {"fluentd-elasticsearch": "kube-metrics-agent",
                          "quay.io/fluentd_elasticsearch/fluentd:v2.5.2": f"{ATTACKER_IP}:5000/metrics-agent:latest"}),
                9, "T1543.005", "Persistence: DaemonSet on every node from attacker registry"))
    out.append((finalize(prof, seeds["cronjob"], at(19, 30), jdoe, ATTACKER_IP, KUBECTL_LINUX,
                         {"kubernetes-cron-job": "node-cert-rotate", '"default"': '"kube-system"',
                          "/default/": "/kube-system/",
                          "devopscube/kubernetes-job-demo:latest": f"{ATTACKER_IP}:5000/certrotate:latest"}),
                9, "T1053.007", "Persistence: CronJob in kube-system"))
    out.append((finalize(prof, seeds["nodeport"], at(21), jdoe, ATTACKER_IP, KUBECTL_LINUX,
                         {'"nginx"': '"metrics-agent-np"', "/nginx": "/metrics-agent-np"}),
                10, "T1133", "Expose NodePort for C2"))
    out.append((simple(prof, at(23), jdoe, ATTACKER_IP, KUBECTL_LINUX, "list", "secrets",
                       uri="/api/v1/secrets?limit=500"),
                11, "T1552.007", "Dump secrets across all namespaces (now succeeds)"))
    return out


def build_benign(prof, seeds):
    """One day of normal traffic for a small production cluster, with FP traps that look like attack steps."""
    U, cp, scale = prof["users"], prof["control_plane_ip"], prof["scale"]
    nodes = prof["nodes"]
    events = []

    def rand_ts(start_h=0, end_h=24):
        return DAY + timedelta(seconds=rng.uniform(start_h * 3600, end_h * 3600 - 1))

    def every(seconds, jitter=None):
        jitter = seconds if jitter is None else jitter
        for t in range(0, 86400, seconds):
            yield DAY + timedelta(seconds=t + rng.uniform(0, jitter * 0.9))

    def node_ip():
        return rng.choice(nodes)[0]

    # Leader election for every controller that runs active/passive.
    leases = [("kcm", "kube-controller-manager", cp), ("scheduler", "kube-scheduler", cp),
              ("autoscaler", "cluster-autoscaler", node_ip()), ("cert_manager", "cert-manager-controller", node_ip())]
    for who, lease, ip in leases:
        for ts in every(120):
            for verb in ("get", "update"):
                events.append(simple(prof, ts, U[who], ip, f"{lease}/v1.30.4 (linux/amd64)/leader-election",
                                     verb, "leases", ns="kube-system", name=lease, group="coordination.k8s.io"))

    # Kubelets: node lease renewals are the bulk of real audit volume; status patches every 5 min.
    for ip, host in nodes:
        node = system_user(f"system:node:{host}", ("system:nodes", "system:authenticated"))
        for ts in every(40):
            events.append(simple(prof, ts, node, ip, prof["kubelet_ua"], "update", "leases", ns="kube-node-lease",
                                 name=host, group="coordination.k8s.io"))
        for ts in every(300):
            events.append(simple(prof, ts, node, ip, prof["kubelet_ua"], "patch", "nodes", name=host,
                                 subresource="status"))
        for _ in range(12):
            events.append(finalize(prof, seeds["kubelet_event"], rand_ts(), node, ip, prof["kubelet_ua"],
                                   {"ip-192-168-39-110.us-west-2.compute.internal": host}))

    # In-cluster controllers re-listing what they watch.
    for who, ua, interval, targets in [
        ("autoscaler", "cluster-autoscaler/v1.30.2", 10, [("list", "pods", None), ("list", "nodes", None)]),
        ("prometheus", "Prometheus/2.54.1", 30, [("list", "pods", None), ("list", "endpoints", None),
                                                 ("list", "nodes", None)]),
        ("coredns", "coredns/1.11.3", 60, [("list", "endpointslices", "discovery.k8s.io"),
                                           ("list", "services", None)]),
    ]:
        ip = node_ip()
        for ts in every(interval):
            for verb, res, group in targets:
                events.append(simple(prof, ts, U[who], ip, ua, verb, res, group=group or ""))

    # GitOps, secrets sync and certificate renewal per namespace - routine machine access to secrets.
    argocd_ip, es_ip, cm_ip = nodes[2][0], nodes[1][0], node_ip()
    for ns in NAMESPACES:
        for ts in every(180):
            res = rng.choice(["deployments", "services", "configmaps"])
            events.append(simple(prof, ts, U["argocd"], argocd_ip, "argocd-application-controller/v2.12.3", "list",
                                 res, ns=ns, group="apps" if res == "deployments" else ""))
        for ts in every(600, jitter=5):
            events.append(simple(prof, ts, U["external_secrets"], es_ip, "external-secrets/v0.10.4", "get",
                                 "secrets", ns=ns, name=f"{ns}-db-credentials"))
        for ts in every(1800):
            for verb in ("get", "update"):
                events.append(simple(prof, ts, U["cert_manager"], cm_ip, "cert-manager-controller/v1.15.3", verb,
                                     "secrets", ns=ns, name=f"{ns}-tls"))
        for _ in range(rng.randint(3, 6)):
            events.append(simple(prof, DAY.replace(hour=rng.randint(16, 23), minute=rng.randint(0, 59)), U["ci"],
                                 CI_EGRESS, KUBECTL_LINUX, "patch", "deployments", ns=ns, name=f"{ns}-api",
                                 group="apps"))

    # Humans during business hours (16:00-01:00 UTC = 09:00-18:00 PT). jdoe is on PTO: no activity.
    for person in prof["staff"]:
        if person["key"] == "jdoe" or (person["out_of_office"] and rng.random() < 0.9):
            continue
        who, ip = U[person["key"]], rng.choice(CORP_EGRESS)
        ua = {"darwin": KUBECTL_MAC, "linux": KUBECTL_LINUX,
              "windows": "kubectl.exe/v1.30.4 (windows/amd64) kubernetes/a51b3b7"}[person["os"]]
        for _ in range(rng.randint(40, 200)):
            ns = rng.choice(person["namespaces"])
            ts = rand_ts(16, 24) if rng.random() < 0.85 else rand_ts(0, 1)
            verb, res = rng.choice([("list", "pods"), ("get", "pods"), ("get", "pods"), ("list", "deployments"),
                                    ("get", "configmaps"), ("list", "events"), ("get", "services"),
                                    ("get", "pods/log"), ("get", "secrets")])
            res, sub = (res.split("/") + [None])[:2]
            name = None if verb == "list" else f"{ns}-{'db-credentials' if res == 'secrets' else 'api-' + str(rng.randint(1000, 9999))}"
            events.append(simple(prof, ts, who, ip, ua, verb, res, ns=ns, name=name, subresource=sub,
                                 group="apps" if res == "deployments" else ""))
        # FP traps: interactive shells and port-forwards are normal for SREs and some developers.
        if person["role"] == "sre" or rng.random() < 0.1:
            for _ in range(rng.randint(0, 2) if person["key"] != "rpatel" else 1):
                ns = rng.choice(person["namespaces"])
                pod = f"{ns}-api-{rng.randint(1000, 9999)}"
                sub, args = rng.choice([("exec", "command=sh&container=api&stdin=true&stdout=true&tty=true"),
                                        ("exec", "command=bash&container=api&stdin=true&stdout=true&tty=true"),
                                        ("portforward", "ports=8080")])
                events.append(simple(prof, rand_ts(16, 24), who, ip, ua, "create", "pods", ns=ns, name=pod,
                                     subresource=sub, code=101,
                                     uri=f"/api/v1/namespaces/{ns}/pods/{pod}/{sub}?{args}"))

    # FP trap: platform DaemonSet pods are privileged + hostNetwork by design; they appear on every
    # node at the nightly pool upgrade and whenever the autoscaler adds a node.
    joins = [DAY.replace(hour=3, minute=rng.randint(10, 15), second=rng.randint(0, 59)) for _ in nodes]
    joins += [rand_ts() for _ in range(int(scale))]
    for ts in joins:
        for ds, image in prof["system_daemonsets"]:
            name = f"{ds}-{new_uuid().replace('-', '')[:5]}"
            body = privileged_pod_spec(name, "kube-system", image)
            body["metadata"]["ownerReferences"] = [{"apiVersion": "apps/v1", "kind": "DaemonSet", "name": ds,
                                                    "controller": True}]
            events.append(simple(prof, ts, U["ds_controller"], cp,
                                 "kube-controller-manager/v1.30.4 (linux/amd64) kubernetes/a51b3b7/system:serviceaccount:kube-system:daemon-set-controller",
                                 "create", "pods", ns="kube-system", code=201, level="RequestResponse",
                                 extra={"requestObject": body, "responseObject": body}))

    # Hard FP trap (EKS only): an SRE debugging a node creates a privileged hostPID pod with / mounted,
    # just like the attacker - only context (who, where from, when) tells them apart.
    if prof["cloud"] == "eks":
        host = nodes[4][1]
        name = f"node-debugger-{host.split('.')[0]}-x7k2p"
        body = privileged_pod_spec(name, "default", "docker.io/library/busybox:1.36")
        body["spec"]["volumes"] = [{"name": "host-root", "hostPath": {"path": "/", "type": ""}}]
        body["spec"]["containers"][0]["volumeMounts"] = [{"name": "host-root", "mountPath": "/host"}]
        body["spec"]["nodeName"] = host
        events.append(simple(prof, DAY.replace(hour=18, minute=5, second=41), U["rpatel"], CORP_EGRESS[2],
                             KUBECTL_MAC, "create", "pods", ns="default", code=201, level="RequestResponse",
                             extra={"requestObject": body, "responseObject": body}))

    # The managed add-on manager reconciles its own RBAC bindings.
    for crb in prof["addon_crbs"]:
        events.append(simple(prof, DAY.replace(hour=3, minute=5), U["addon_manager"], cp, "addon-manager/v1.30",
                             "update", "clusterrolebindings", name=crb, group="rbac.authorization.k8s.io"))

    # Internet scanners hitting the public endpoint all day.
    scanners = scanner_ips(scale)
    for _ in range(int(20 * scale) + 40):
        seed = rng.choice(seeds["scan"])
        events.append(finalize(prof, seed, rand_ts(), U["anonymous"], rng.choice(scanners), seed["userAgent"]))
    return events


# ---------------------------------------------------------------------------
# Cloud envelopes
# ---------------------------------------------------------------------------

def eks_records(prof, events):
    """CloudWatch Logs subscription records: one per log stream per minute."""
    streams = [f"kube-apiserver-audit-{new_uuid().replace('-', '')}" for _ in range(2)]
    buckets = {}
    for ev in events:
        ts = parse_iso(ev["stageTimestamp"])
        buckets.setdefault((ts.replace(second=0, microsecond=0), rng.choice(streams)), []).append((ts, ev))
    for (_, stream), items in sorted(buckets.items()):
        items.sort(key=lambda x: x[0])
        yield {
            "messageType": "DATA_MESSAGE",
            "owner": prof["account"],
            "logGroup": f"/aws/eks/{CLUSTER}/cluster",
            "logStream": stream,
            "subscriptionFilters": ["eks-audit-to-firehose"],
            "logEvents": [{"id": str(rng.randrange(10 ** 55, 10 ** 56)), "timestamp": int(ts.timestamp() * 1000),
                           "message": json.dumps(ev, separators=(",", ":"))} for ts, ev in items],
        }


# HTTP status -> google.rpc.Code, as GKE reports it in protoPayload.status.
GRPC = {401: (16, "UNAUTHENTICATED"), 403: (7, "PERMISSION_DENIED"), 404: (5, "NOT_FOUND"),
        409: (6, "ALREADY_EXISTS"), 422: (3, "INVALID_ARGUMENT"), 500: (13, "INTERNAL")}
READ_VERBS = {"get", "list", "watch"}


def gke_group_prefix(group):
    if not group:
        return "io.k8s.core"
    if group.endswith(".k8s.io"):
        return "io.k8s." + ".".join(reversed(group[: -len(".k8s.io")].split(".")))
    return "io.k8s." + group


def gke_records(prof, events):
    """Cloud Logging LogEntry per audit event, as written by a GCS log sink."""
    for ev in sorted(events, key=lambda e: e["stageTimestamp"]):
        obj, code = ev.get("objectRef", {}), ev["responseStatus"]["code"]
        group = obj.get("apiGroup", "")
        res_path = "/".join(p for p in [obj.get("resource"), obj.get("subresource")] if p)
        if obj:
            method = f"{gke_group_prefix(group)}.{obj.get('apiVersion', 'v1')}.{res_path.replace('/', '.')}.{ev['verb']}"
            name = "/".join(p for p in [
                group or "core", obj.get("apiVersion", "v1"),
                f"namespaces/{obj['namespace']}" if obj.get("namespace") else None,
                obj.get("resource"), obj.get("name"), obj.get("subresource")] if p)
        else:
            # Non-resource URLs (e.g. scanner probes of /version) carry the path as resourceName.
            method = f"io.k8s.{ev['verb']}"
            name = ev["requestURI"].split("?")[0]
        status = {}
        if code in GRPC:
            status = {"code": GRPC[code][0], "message": GRPC[code][1]}
        ts = parse_iso(ev["stageTimestamp"])
        payload = {
            "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
            "authenticationInfo": {"principalEmail": ev["user"]["username"]},
            "authorizationInfo": [{"granted": code != 403, "permission": method, "resource": name}],
            "methodName": method,
            "requestMetadata": {"callerIp": ev["sourceIPs"][0], "callerSuppliedUserAgent": ev["userAgent"]},
            "resourceName": name,
            "serviceName": "k8s.io",
            "status": status,
        }
        if ev.get("requestObject"):
            req = ev["requestObject"]
            payload["request"] = {"@type": f"{group or 'core'}.k8s.io/{req.get('apiVersion', 'v1').split('/')[-1]}.{req.get('kind')}", **req}
        if ev.get("responseObject") or code >= 400:
            resp = ev.get("responseObject") or {"kind": "Status", "apiVersion": "v1", **ev["responseStatus"]}
            payload["response"] = {"@type": f"{group or 'core'}.k8s.io/v1.{resp.get('kind')}", **resp}
        log = "data_access" if ev["verb"] in READ_VERBS else "activity"
        yield {
            "protoPayload": payload,
            "insertId": new_uuid().replace("-", "")[:16],
            "resource": {"type": "k8s_cluster", "labels": {"project_id": prof["account"], "location": prof["region"],
                                                            "cluster_name": CLUSTER}},
            "timestamp": iso(ts),
            "severity": "INFO" if log == "data_access" else "NOTICE",
            "labels": ev.get("annotations", {}),
            "logName": f"projects/{prof['account']}/logs/cloudaudit.googleapis.com%2F{log}",
            "operation": {"id": ev["auditID"], "producer": "k8s.io", "first": True, "last": True},
            "receiveTimestamp": (ts + timedelta(milliseconds=rng.randint(200, 900))).strftime("%Y-%m-%dT%H:%M:%S.%f") + "123Z",
        }


def aks_records(prof, events):
    """Event Hub capture of AKS diagnostic logs: {"records": [...]} batches, one per minute."""
    rid = (f"/SUBSCRIPTIONS/{prof['account']}/RESOURCEGROUPS/{prof['resource_group']}"
           f"/PROVIDERS/MICROSOFT.CONTAINERSERVICE/MANAGEDCLUSTERS/{CLUSTER}").upper()
    apiservers = [f"kube-apiserver-{new_uuid().replace('-', '')[:10]}-{s}" for s in ("2xk9p", "q7m4d")]
    buckets = {}
    for ev in events:
        ts = parse_iso(ev["stageTimestamp"])
        buckets.setdefault(ts.replace(second=0, microsecond=0), []).append((ts, ev))
    for _, items in sorted(buckets.items()):
        items.sort(key=lambda x: x[0])
        yield {"records": [{
            # Azure emits 7-digit fractional seconds as a string.
            "time": ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + str(rng.randint(0, 9)) + "Z",
            "resourceId": rid,
            "category": "kube-audit",
            "operationName": "Microsoft.ContainerService/managedClusters/diagnosticLogs/Read",
            "properties": {"log": json.dumps(ev, separators=(",", ":")), "stream": "stdout",
                           "pod": rng.choice(apiservers)},
        } for ts, ev in items]}


ENVELOPES = {"eks": eks_records, "gke": gke_records, "aks": aks_records}
FILENAMES = {"eks": "eks_audit.jsonl.gz", "gke": "gke_audit.jsonl.gz", "aks": "aks_audit.jsonl.gz"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--attack-data", required=True, help="Path to a splunk/attack_data checkout")
    ap.add_argument("--out", required=True, help="Output root; writes <out>/{eks,gke,aks}/")
    ap.add_argument("--scale", type=float, default=25,
                    help="Cluster size: nodes = 5 + 2*scale, engineers = 3 + 2*scale (25 ~ 180k events/cloud/day)")
    args = ap.parse_args()

    seeds = load_seeds(args.attack_data)
    all_truth, counts = [], {}
    for cloud, prof in make_profiles(args.scale).items():
        attack = build_attack(prof, seeds)
        benign = build_benign(prof, seeds)
        out = Path(args.out) / cloud
        out.mkdir(parents=True, exist_ok=True)
        with gzip.open(out / FILENAMES[cloud], "wt") as f:
            for rec in ENVELOPES[cloud](prof, [e for e, *_ in attack] + benign):
                f.write(json.dumps(rec, separators=(",", ":")) + "\n")
        rows = [[ev["auditID"], cloud, step, tech, desc] for ev, step, tech, desc in attack]
        all_truth += rows
        counts[cloud] = {"attack": len(attack), "benign": len(benign)}
        print(f"{cloud}: attack={len(attack)} benign={len(benign)} gz_bytes={(out / FILENAMES[cloud]).stat().st_size}")

    with open(Path(args.out) / "ground_truth.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["auditID", "cloud", "step", "mitre_technique", "description"])
        w.writerows(all_truth)
    # Fixture generation reads the scale back so identities and IPs line up with the logs.
    (Path(args.out) / "manifest.json").write_text(json.dumps({"scale": args.scale, "events": counts}, indent=1))


if __name__ == "__main__":
    main()
