def files($prefix): [.files|to_entries[]|select(.key|startswith($prefix))|.value]|add//0;
def pct($p): sort | .[((length*$p|ceil)-1)];
(["run","logical_code_B","logical_pkce_B","logical_interaction_B","command_B","sqlite_delta_B","sidecar_delta_B","qlog_delta_B","object_retained_delta_B","uploaded_delta_B","alloc_B","issue_p50_ns","issue_p95_ns","issue_p99_ns","consume_p50_ns","consume_p95_ns","consume_p99_ns","archive_B","export_ns","extract_ns","restore_ns","open_ns"]|@tsv),
(.[]|[.run,.logical[0][2],.logical[1][2],.logical[2][2],.workload.issue_execute_request_json_bytes,
(.after_workload.files["data/sqlite.db"]-.control.files["data/sqlite.db"]),
((.after_workload|files("data/sqlite.db-"))-(.control|files("data/sqlite.db-"))),
((.after_workload|files("data/qlog/"))-(.control|files("data/qlog/"))),
((.after_workload|files("objects/"))-(.control|files("objects/"))),
(.after_workload.object_stats.bytes_uploaded-.control.object_stats.bytes_uploaded),.workload.allocated_bytes,
(.workload.issue_ns|pct(0.5)),(.workload.issue_ns|pct(0.95)),(.workload.issue_ns|pct(0.99)),
(.workload.consume_ns|pct(0.5)),(.workload.consume_ns|pct(0.95)),(.workload.consume_ns|pct(0.99)),
.recovery.archive_bytes,.recovery.export_ns,.recovery.extract_ns,.recovery.restore_ns,.recovery.open_ns]|@tsv)
