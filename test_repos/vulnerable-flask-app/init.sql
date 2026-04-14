CREATE TABLE users (
    id serial PRIMARY KEY,
    name text,
    email text
);

INSERT INTO users (name, email) VALUES
    ('Alice Example', 'alice@example.com'),
    ('Bob Sample', 'bob@example.com'),
    ('Carol Demo', 'carol@example.com');
