CREATE TABLE config_node_guards (
    uuid TEXT PRIMARY KEY NOT NULL,
    rate_limit_json TEXT NOT NULL,
    allow_json TEXT NOT NULL,
    check_sum_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
