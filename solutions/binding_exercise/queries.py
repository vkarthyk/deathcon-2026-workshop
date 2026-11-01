"""Facilitator answer queries; never loaded into participant TODO cells."""
from workshop.behavioral import ROOT


def detection(cloud):
    name = 'normalized_success' if cloud == 'normalized-success' else cloud
    sql = (ROOT / 'detection/simple_cluster_admin' / (name + '.sql')).read_text()
    return sql.replace('enterprise.k8s_ocsf', 'main.binding_events') if cloud.startswith('normalized') else sql
