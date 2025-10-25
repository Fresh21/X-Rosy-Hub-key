const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const PORT = process.env.PORT || 3000;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "REPLACE_THIS_WITH_STRONG_TOKEN";
const KEYS_FILE = process.env.KEYS_FILE || path.join(__dirname, 'keys.json');

const app = express();
app.use(helmet());
app.use(cors());
app.use(bodyParser.json({ limit: '10kb' }));
app.use(morgan('combined'));

const verifyLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  message: { ok: false, error: 'rate_limited' }
});

function loadKeys() {
  try {
    if (!fs.existsSync(KEYS_FILE)) fs.writeFileSync(KEYS_FILE, JSON.stringify({}, null, 2));
    return JSON.parse(fs.readFileSync(KEYS_FILE, 'utf8') || '{}');
  } catch (e) { console.error(e); return {}; }
}
function saveKeys(obj) {
  try { fs.writeFileSync(KEYS_FILE, JSON.stringify(obj, null, 2), 'utf8'); return true; }
  catch (e) { console.error(e); return false; }
}

app.get('/', (req, res) => res.json({ ok: true, service: "key-verify-api", time: new Date().toISOString() }));

app.post('/verify', verifyLimiter, (req, res) => {
  const key = (req.body.key || '').toString().trim();
  const hwid = req.body.hwid ? req.body.hwid.toString().trim() : null;
  if (!key) return res.status(400).json({ ok: false, error: 'no_key' });
  const keys = loadKeys(); const info = keys[key];
  if (!info || !info.valid) return res.status(403).json({ ok: false, error: 'invalid_key' });
  if (hwid && (!info.hwid || info.hwid === null)) { info.hwid = hwid; info.bound_at = new Date().toISOString(); saveKeys(keys); }
  else if (hwid && info.hwid && info.hwid !== hwid) { return res.status(403).json({ ok: false, error: 'hwid_mismatch' }); }
  return res.json({ ok: true, msg: 'valid', note: info.note || null, key_info: { key, created_at: info.created_at || null, hwid: info.hwid || null } });
});

function requireAdmin(req, res, next) {
  const token = (req.headers['x-admin-token'] || '').toString();
  if (!token || token !== ADMIN_TOKEN) return res.status(401).json({ ok: false, error: 'unauthorized' });
  next();
}

app.post('/admin/add', requireAdmin, (req, res) => {
  const key = (req.body.key || "").toString().trim() || uuidv4();
  const note = req.body.note || "";
  const keys = loadKeys();
  if (keys[key] && keys[key].valid) return res.status(400).json({ ok: false, error: 'key_exists' });
  keys[key] = { valid: true, note, created_at: new Date().toISOString(), hwid: null };
  if (!saveKeys(keys)) return res.status(500).json({ ok: false, error: 'save_failed' });
  res.json({ ok: true, key });
});

app.post('/admin/revoke', requireAdmin, (req, res) => {
  const key = (req.body.key || "").toString().trim();
  if (!key) return res.status(400).json({ ok: false, error: 'no_key' });
  const keys = loadKeys();
  if (!keys[key]) return res.status(404).json({ ok: false, error: 'not_found' });
  keys[key].valid = false; keys[key].revoked_at = new Date().toISOString();
  if (!saveKeys(keys)) return res.status(500).json({ ok: false, error: 'save_failed' });
  res.json({ ok: true, key, revoked: true });
});

app.get('/admin/list', requireAdmin, (req, res) => {
  const keys = loadKeys();
  res.json({ ok: true, total: Object.keys(keys).length, keys });
});

app.listen(PORT, () => {
  console.log(`✅ Key Verify API listening on port ${PORT}`);
});
