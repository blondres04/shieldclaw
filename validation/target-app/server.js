'use strict';

const express = require('express');
const { Pool } = require('pg');

const app = express();
app.use(express.json());

const pool = new Pool({
  host: process.env.PGHOST || 'localhost',
  port: Number(process.env.PGPORT) || 5432,
  user: process.env.PGUSER || 'targetapp',
  password: process.env.PGPASSWORD || 'targetapp',
  database: process.env.PGDATABASE || 'targetapp',
});

function parseUserId(raw) {
  const id = Number.parseInt(String(raw), 10);
  if (!Number.isInteger(id) || id < 1) {
    return null;
  }
  return id;
}

app.get('/users', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, name, email FROM users ORDER BY id ASC'
    );
    res.json(result.rows);
  } catch (err) {
    console.error('GET /users failed:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.get('/users/:id', async (req, res) => {
  const id = parseUserId(req.params.id);
  if (id === null) {
    return res.status(400).json({ error: 'Invalid user id' });
  }
  try {
    const result = await pool.query(
      'SELECT id, name, email FROM users WHERE id = $1',
      [id]
    );
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error('GET /users/:id failed:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.post('/users', async (req, res) => {
  const { name, email } = req.body || {};
  if (
    typeof name !== 'string' ||
    typeof email !== 'string' ||
    name.trim() === '' ||
    email.trim() === ''
  ) {
    return res
      .status(400)
      .json({ error: 'name and email are required non-empty strings' });
  }

  try {
    const result = await pool.query(
      `INSERT INTO users (name, email)
       VALUES ($1, $2)
       RETURNING id, name, email`,
      [name.trim(), email.trim()]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'Email already exists' });
    }
    console.error('POST /users failed:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.delete('/users/:id', async (req, res) => {
  const id = parseUserId(req.params.id);
  if (id === null) {
    return res.status(400).json({ error: 'Invalid user id' });
  }
  try {
    const result = await pool.query('DELETE FROM users WHERE id = $1', [id]);
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.status(204).send();
  } catch (err) {
    console.error('DELETE /users/:id failed:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

const port = Number(process.env.PORT) || 3000;
app.listen(port, '0.0.0.0', () => {
  console.log(`target-app listening on port ${port}`);
});
