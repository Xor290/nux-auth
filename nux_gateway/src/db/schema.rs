// @generated automatically by Diesel CLI.

diesel::table! {
    config_node_guards (uuid) {
        uuid -> Text,
        rate_limit_json -> Text,
        allow_json -> Text,
        check_sum_json -> Text,
        updated_at -> Text,
    }
}
