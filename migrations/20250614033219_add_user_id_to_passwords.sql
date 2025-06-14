-- Add migration script here
-- New migration: Add user_id to passwords table
-- sqlx migrate add add_user_id_to_passwords

ALTER TABLE passwords ADD COLUMN user_id UUID NOT NULL;

-- If you want to link it as a foreign key:
ALTER TABLE passwords ADD CONSTRAINT fk_user
FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
-- (Note: If you already have existing password entries from previous tests, you might need to set a default user_id for them before adding NOT NULL or FK constraint.)