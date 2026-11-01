"""Fields the Lab 2 autograder checks, shared by the golden-file builder and the tests."""

# Each graded field as a SQL expression over an ocsf_<cloud> row.
GRADED_FIELDS = {
    "activity_id": "activity_id",
    "time": "strftime(time, '%Y-%m-%dT%H:%M:%S')",
    "status_id": "status_id",
    "api.operation": "api.operation",
    "resources.type": "resources[1].type",
    "resources.namespace": "resources[1].namespace",
    "resources.name": "resources[1].name",
    "actor.user.name": "actor.user.name",
    "actor.user.uid": "actor.user.uid",
    "actor.user.email_addr": "actor.user.email_addr",
    "actor.user.type": "actor.user.type",
    "cloud.account.uid": "cloud.account.uid",
    "cloud.account.labels.cluster_name": "cloud.account.labels['cluster_name']",
    "src_endpoint.ip": "src_endpoint.ip",
}

# Fields that must be identical across clouds for every attack step: the point of normalizing.
CROSS_CLOUD_FIELDS = ["activity_id", "status_id", "api.operation", "resources.type", "resources.namespace",
                      "resources.name", "actor.user.email_addr", "actor.user.type", "src_endpoint.ip",
                      "cloud.account.labels.cluster_name"]


def select_graded(view):
    cols = ", ".join(f'({expr})::VARCHAR AS "{name}"' for name, expr in GRADED_FIELDS.items())
    return f"SELECT metadata.uid AS uid, {cols} FROM {view}"
