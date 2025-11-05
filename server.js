import express from "express";
import pg from "pg";
import cors from "cors"
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';
import crypto from 'crypto';



const app = express();
dotenv.config();

const {Pool} = pg;
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

app.use(cors())
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

let config = {
  sql_injection_enabled: false,
  broken_auth_enabled: false
};

const sessions = {};

const failedAttempts = {};

function bfKey(ip) {
  return `${ip || 'no-ip'}`;
}

const BF_MAX_ATTEMPTS = 5;
const BF_WINDOW_MS = 15 * 60 * 1000;
const BF_LOCK_MS = 15 * 60 * 1000;

function isLocked(key) {
  const rec = failedAttempts[key];
  if (!rec) return false;
  if (rec.lockedUntil && Date.now() < rec.lockedUntil) return true;
  return false;
}

function recordFailedAttempt(key) {
  const now = Date.now();
  if (!failedAttempts[key]) {
    failedAttempts[key] = { count: 1, firstAttemptTs: now, lockedUntil: null };
    return;
  }
  const rec = failedAttempts[key];
  if (now - rec.firstAttemptTs > BF_WINDOW_MS) {
    rec.count = 1;
    rec.firstAttemptTs = now;
    rec.lockedUntil = null;
    return;
  }
  rec.count += 1;
  if (rec.count >= BF_MAX_ATTEMPTS) {
    rec.lockedUntil = now + BF_LOCK_MS;
  }
}

function clearFailedAttempts(key) {
  delete failedAttempts[key];
}

function createSid() {
  return crypto.randomBytes(24).toString('hex');
}

app.get('/api/config', (req, res) => res.json(config));

app.post('/api/config', (req, res) => {
  const { key, value } = req.body;
  if (key in config) {
    config[key] = !!value;
    return res.json({ ok: true, config });
  }
  res.status(400).json({ ok: false, message: 'Unknown config' });
});

app.get("/", (req, res) => {
  res.send("Ranjivi backend radi");
});

app.get('/api/sql', async (req, res) => {
  const q = req.query.q || '';
  const client = await pool.connect();
  try {
    if (config.sql_injection_enabled) {
      const sql = `SELECT id, username, email, balance FROM users WHERE username = '${q}'`;
      const result = await client.query(sql);
      return res.json({ rows: result.rows });
    } else {
      const sql = `SELECT id, username, email, balance FROM users WHERE username = $1`;
      const result = await client.query(sql, [q]);
      return res.json({ rows: result.rows });
    }
  } catch (err) {
    return res.status(500).json({ err: err.message });
  } finally {
    client.release();
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  const ip = req.ip || req.headers['x-forwarded-for'] || 'unknown';

  if (!username) return res.status(400).json({ ok: false, message: 'Username required' });

  const client = await pool.connect();
  try {
    const r = await client.query('SELECT id, username, password FROM users WHERE username = $1', [username]);

    const user = r.rows[0];

    if (config.broken_auth_enabled) {
      if (r.rowCount === 0) {
        return res.status(401).json({ ok: false, message: 'Username dosnt exist in database' });
      }
      const passOk = (password === user.password);
      if (!passOk) {
        return res.status(401).json({ ok: false, message: 'Incorrect password' });
      }
      res.cookie('session', `${user.username}-token`, { httpOnly: false });
      return res.json({ ok: true, message: 'Logged in (vulnerable). Session cookie set and readable by JS.' });
    } else {
      const key = bfKey(ip);
      if (isLocked(key)) {
        return res.status(429).json({ ok: false, message: 'Account temporarily locked due to too many failed attempts' });
      }
      if (r.rowCount === 0) {
        recordFailedAttempt(key);
        return res.status(401).json({ ok: false, message: 'Invalid credentials' });
      }

      const match = (password === user.password);
      if (!match) {
        recordFailedAttempt(key);
        return res.status(401).json({ ok: false, message: 'Invalid credentials'} );
      }

      clearFailedAttempts(key);
      const sid = createSid();
      sessions[sid] = { username: user.username, createdAt: Date.now() };
      res.cookie('sid', sid, { httpOnly: true });
      return res.json({ ok: true, message: 'Logged in (secure). HttpOnly session cookie set.' });
    }
  } catch (err) {
    console.error('Login error', err);
    return res.status(500).json({ ok: false, err: err.message });
  } finally {
    client.release();
  }
});

app.post('/api/logout', (req, res) => {
  if (config.broken_auth_enabled) {
    res.clearCookie('session');
    return res.json({ ok: true, message: 'Logged out (vulnerable)' });
  } else {
    const sid = req.cookies.sid;
    if (sid && sessions[sid]) delete sessions[sid];
    res.clearCookie('sid');
    return res.json({ ok: true, message: 'Logged out (secure)' });
  }
});




const port = process.env.PORT;
app.listen(port, () => console.log(`Server radi na portu ${port}`));