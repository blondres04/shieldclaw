-- Baseline schema and sample data for Shield Claw target-app (first init only).
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE
);

INSERT INTO users (name, email) VALUES
    ('Alice Example', 'alice@example.com'),
    ('Bob Example', 'bob@example.com'),
    ('Carol Example', 'carol@example.com')
ON CONFLICT (email) DO NOTHING;
