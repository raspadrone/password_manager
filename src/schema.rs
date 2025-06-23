// @generated automatically by Diesel CLI.

diesel::table! {
    passwords (id) {
        id -> Uuid,
        #[max_length = 255]
        key -> Varchar,
        value -> Text,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        user_id -> Uuid,
        notes -> Nullable<Text>,
    }
}

diesel::table! {
    users (id) {
        id -> Uuid,
        #[max_length = 255]
        username -> Varchar,
        hashed_password -> Text,
        created_at -> Timestamptz,
    }
}

diesel::joinable!(passwords -> users (user_id));

diesel::allow_tables_to_appear_in_same_query!(
    passwords,
    users,
);
