-- Add migration script here

CREATE TABLE IF NOT EXISTS passwords (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key VARCHAR(255) NOT NULL UNIQUE,
    value TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- You'll need to create a function to update `updated_at` on changes.
-- This is a common pattern for "last modified" timestamps.
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE OR REPLACE TRIGGER update_passwords_updated_at
    BEFORE UPDATE ON passwords
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

