const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const multer = require('multer');
const { Server } = require('socket.io');

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const DATABASE_URL = process.env.DATABASE_URL || ''; // set on Render (Neon Postgres) for permanent storage
const DB_FILE = path.join(__dirname, 'db.json');

// ---------- DB ----------
// Local dev: JSON file. Production (DATABASE_URL set): the whole db object is
// persisted into a single Postgres row, so users/items/images survive forever.
let db = { users: [], items: [], nextItemId: 1, nextInstanceId: 1, tokens: {} };
let pgPool = null;

async function loadDb() {
  if (DATABASE_URL) {
    const { Pool } = require('pg');
    const isLocal = /localhost|127\.0\.0\.1/.test(DATABASE_URL);
    pgPool = new Pool({ connectionString: DATABASE_URL, ssl: isLocal ? false : { rejectUnauthorized: false } });
    await pgPool.query('CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value JSONB)');
    const r = await pgPool.query("SELECT value FROM kv WHERE key='db'");
    if (r.rows.length) db = r.rows[0].value;
    console.log('DB: Postgres connected,', db.users.length, 'users,', db.items.length, 'items');
  } else if (fs.existsSync(DB_FILE)) {
    try { db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch (e) { console.error('db load failed', e); }
    console.log('DB: local file,', db.users.length, 'users');
  }
  if (!db.tokens) db.tokens = {};
  if (!db.payouts) db.payouts = [];
  if (!db.nextPayoutId) db.nextPayoutId = 1;
  if (!db.requests) db.requests = [];
  if (!db.nextRequestId) db.nextRequestId = 1;
  if (!db.settings) db.settings = { depositLink: '', withdrawLink: '' };
  if (!db.totalUpgrades) db.totalUpgrades = 0;
}

let saveTimer = null;
function saveDb() {
  if (pgPool) {
    clearTimeout(saveTimer);
    saveTimer = setTimeout(() => {
      pgPool.query("INSERT INTO kv(key, value) VALUES('db', $1) ON CONFLICT (key) DO UPDATE SET value = $1",
        [JSON.stringify(db)]).catch(e => console.error('pg save failed', e));
    }, 250);
  } else {
    fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
  }
}

// ---------- helpers ----------
function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 32).toString('hex');
}
function sha256(s) { return crypto.createHash('sha256').update(s).digest('hex'); }
function itemDef(itemId) { return db.items.find(i => i.id === itemId); }
function instanceValue(inst) { const d = itemDef(inst.itemId); return d ? d.value : 0; }
function potValue(instances) { return instances.reduce((s, i) => s + instanceValue(i), 0); }
function publicInstance(inst) {
  const d = itemDef(inst.itemId) || { name: '(deleted item)', value: 0, image: '' };
  return { iid: inst.iid, itemId: inst.itemId, name: d.name, value: d.value, image: d.image };
}
function userByName(name) { return db.users.find(u => u.username.toLowerCase() === String(name).toLowerCase()); }
function recordHistory(user) {
  if (!user.history) user.history = [];
  user.history.push({ t: Date.now(), v: potValue(user.inventory) });
  if (user.history.length > 300) user.history = user.history.slice(-300);
}
// ---- levels ----
// XP from playing games: base 10 + sqrt(pot). Winner gets 1.5x. Balanced curve:
// level L is reached at 100*(L-1)^2 XP -> L2 at 100, L3 at 400, L5 at 1600, L10 at 8100
function levelFromXp(xp) { return Math.floor(Math.sqrt((xp || 0) / 500)) + 1; }
function xpForLevel(l) { return 500 * (l - 1) * (l - 1); }

function authUser(req) {
  const t = req.headers['x-token'];
  if (!t || !db.tokens[t]) return null;
  return db.users.find(u => u.id === db.tokens[t]) || null;
}
function isAdmin(req) { return req.headers['x-admin-password'] === ADMIN_PASSWORD; }
function issueToken(user) {
  const t = crypto.randomBytes(24).toString('hex');
  db.tokens[t] = user.id;
  const mine = Object.keys(db.tokens).filter(k => db.tokens[k] === user.id);
  if (mine.length > 20) mine.slice(0, mine.length - 20).forEach(k => delete db.tokens[k]);
  saveDb();
  return t;
}

// banned words in usernames (swears, slurs, hate words)
const BANNED_WORDS = ['fuck','fuk','shit','sh1t','bitch','b1tch','cunt','nigger','n1gger','nigga','n1gga','faggot','fag','retard','r3tard','whore','slut','dick','d1ck','cock','pussy','pussi','asshole','rape','rapist','hitler','nazi','kike','spic','chink','coon','tranny','dyke','porn','penis','pen1s','vagina','cum','kys','pedo'];
function usernameAllowed(name) {
  const norm = name.toLowerCase()
    .replace(/0/g, 'o').replace(/1/g, 'i').replace(/3/g, 'e')
    .replace(/4/g, 'a').replace(/5/g, 's').replace(/7/g, 't')
    .replace(/8/g, 'b').replace(/_/g, '');
  const plain = name.toLowerCase().replace(/_/g, '');
  return !BANNED_WORDS.some(w => norm.includes(w) || plain.includes(w));
}
function censorText(text) {
  let out = text;
  BANNED_WORDS.forEach(w => {
    out = out.replace(new RegExp(w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi'), '*'.repeat(w.length));
  });
  return out;
}

// ---------- app ----------
const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// item pictures are stored INSIDE the database as data URIs so they survive
// redeploys and restarts on any host (no filesystem needed)
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 1.5 * 1024 * 1024 } });
function fileToDataUri(file) {
  return 'data:' + (file.mimetype || 'image/png') + ';base64,' + file.buffer.toString('base64');
}

// ---------- auth ----------
app.post('/api/register', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  if (!/^[A-Za-z0-9_]{2,20}$/.test(username)) return res.status(400).json({ error: 'Username: 2-20 letters/numbers/_' });
  if (!usernameAllowed(username)) return res.status(400).json({ error: 'That username is not allowed' });
  if (userByName(username)) return res.status(400).json({ error: 'Username taken' });
  const salt = crypto.randomBytes(16).toString('hex');
  const user = { id: crypto.randomUUID(), username, salt, passHash: hashPassword(password, salt),
                 inventory: [], wins: 0, losses: 0, xp: 0, wagered: 0, money: 0,
                 affEarned: 0, refCount: 0, referredBy: null, affCode: null,
                 history: [{ t: Date.now(), v: 0 }] };
  db.users.push(user); saveDb();
  res.json({ token: issueToken(user), username: user.username });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  const user = userByName(username || '');
  if (!user || hashPassword(password || '', user.salt) !== user.passHash) {
    return res.status(400).json({ error: 'Wrong username or password' });
  }
  res.json({ token: issueToken(user), username: user.username });
});

app.get('/api/me', (req, res) => {
  const user = authUser(req);
  if (!user) return res.status(401).json({ error: 'Not logged in' });
  const lvl = levelFromXp(user.xp);
  res.json({
    username: user.username, wins: user.wins, losses: user.losses,
    xp: user.xp || 0, level: lvl, levelXp: xpForLevel(lvl), nextLevelXp: xpForLevel(lvl + 1),
    inventory: user.inventory.map(publicInstance),
    totalValue: potValue(user.inventory),
    money: user.money || 0,
    gamesPlayed: (user.wins || 0) + (user.losses || 0),
    wagered: user.wagered || 0,
    affEarned: user.affEarned || 0, refCount: user.refCount || 0,
    affCode: user.affCode || '',
    pendingPayout: (db.payouts || []).filter(p => p.userId === user.id && p.status === 'pending').reduce((s, p) => s + p.amount, 0),
    referredBy: user.referredBy ? ((db.users.find(x => x.id === user.referredBy) || {}).username || null) : null,
    roblox: user.roblox || null
  });
});

app.get('/api/items', (req, res) => res.json(db.items));

// marketplace: buy an item with your money (price = item value)
app.post('/api/market/buy', (req, res) => {
  const user = authUser(req);
  if (!user) return res.status(401).json({ error: 'Log in first' });
  const item = itemDef(Number((req.body || {}).itemId));
  if (!item) return res.status(404).json({ error: 'Item not found' });
  if ((user.money || 0) < item.value) return res.status(400).json({ error: 'Not enough money (costs ' + item.value + ', you have ' + (user.money || 0) + ')' });
  user.money = (user.money || 0) - item.value;
  user.inventory.push({ iid: db.nextInstanceId++, itemId: item.id });
  recordHistory(user);
  saveDb();
  pushInventory(user);
  res.json({ ok: true, money: user.money, item: item.name });
});

app.get('/api/profile/:username', (req, res) => {
  const u = userByName(req.params.username);
  if (!u) return res.status(404).json({ error: 'User not found' });
  const lvl = levelFromXp(u.xp);
  res.json({
    username: u.username, wins: u.wins, losses: u.losses,
    xp: u.xp || 0, level: lvl, levelXp: xpForLevel(lvl), nextLevelXp: xpForLevel(lvl + 1),
    totalValue: potValue(u.inventory),
    gamesPlayed: (u.wins || 0) + (u.losses || 0),
    wagered: u.wagered || 0,
    inventory: u.inventory.map(publicInstance),
    history: u.history || [{ t: Date.now(), v: potValue(u.inventory) }],
    games: u.games || [],
    roblox: u.roblox || null
  });
});

// ---------- Roblox account linking (like Bloxlink, but direct) ----------
// Player proves they own a Roblox account by putting a one-time code in their
// Roblox profile "About" section; we check it via Roblox's official public API.
const RBX_WORDS = ['apple','piano','tiger','ocean','candle','river','maple','rocket','silver','mango','falcon','breeze','copper','meadow','pearl','comet','willow','ember','harbor','summit'];
function robloxCode() {
  const w = [];
  for (let i = 0; i < 6; i++) w.push(RBX_WORDS[crypto.randomInt(RBX_WORDS.length)]);
  return w.join(' ');
}
app.post('/api/roblox/link', async (req, res) => {
  const user = authUser(req);
  if (!user) return res.status(401).json({ error: 'Log in first' });
  const name = String((req.body || {}).robloxName || '').trim();
  if (!name || name.length > 30) return res.status(400).json({ error: 'Enter your Roblox username' });
  try {
    const r = await fetch('https://users.roblox.com/v1/usernames/users', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ usernames: [name], excludeBannedUsers: true })
    });
    const j = await r.json();
    const found = j.data && j.data[0];
    if (!found) return res.status(404).json({ error: 'No Roblox user with that name' });
    user.robloxPending = { id: found.id, name: found.name, code: robloxCode() };
    saveDb();
    res.json({ ok: true, robloxName: found.name, robloxId: found.id, code: user.robloxPending.code });
  } catch (e) { res.status(500).json({ error: 'Could not reach Roblox — try again in a moment' }); }
});
app.post('/api/roblox/verify', async (req, res) => {
  const user = authUser(req);
  if (!user) return res.status(401).json({ error: 'Log in first' });
  const p = user.robloxPending;
  if (!p) return res.status(400).json({ error: 'Start the link first (enter your Roblox name)' });
  try {
    const r = await fetch('https://users.roblox.com/v1/users/' + p.id);
    const j = await r.json();
    const desc = String(j.description || '').toLowerCase().replace(/\s+/g, ' ');
    if (!desc.includes(p.code.toLowerCase()))
      return res.status(400).json({ error: 'Code not found in your Roblox About section yet. Paste it there, press Save on Roblox, then try again.' });
    let avatar = '';
    try {
      const t = await fetch('https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds=' + p.id + '&size=48x48&format=Png&isCircular=true');
      const tj = await t.json();
      avatar = (tj.data && tj.data[0] && tj.data[0].imageUrl) || '';
    } catch (e) {}
    user.roblox = { id: p.id, name: j.name || p.name, displayName: j.displayName || '', avatar };
    delete user.robloxPending;
    saveDb();
    res.json({ ok: true, roblox: user.roblox });
  } catch (e) { res.status(500).json({ error: 'Could not reach Roblox — try again in a moment' }); }
});
app.post('/api/roblox/unlink', (req, res) => {
  const user = authUser(req);
  if (!user) return res.status(401).json({ error: 'Log in first' });
  delete user.roblox;
  delete user.robloxPending;
  saveDb();
  res.json({ ok: true });
});

// marketplace: sell an item from your inventory for its full value
app.post('/api/market/sell', (req, res) => {
  const user = authUser(req);
  if (!user) return res.status(401).json({ error: 'Log in first' });
  const iid = Number((req.body || {}).iid);
  const idx = user.inventory.findIndex(i => i.iid === iid);
  if (idx < 0) return res.status(404).json({ error: 'Item not in your inventory' });
  const val = instanceValue(user.inventory[idx]);
  const name = publicInstance(user.inventory[idx]).name;
  user.inventory.splice(idx, 1);
  user.money = (user.money || 0) + val;
  recordHistory(user);
  saveDb();
  pushInventory(user);
  res.json({ ok: true, money: user.money, sold: val, item: name });
});

// ---------- deposit / withdraw ----------
app.get('/api/links', (req, res) => {
  res.json({ deposit: (db.settings || {}).depositLink || '', withdraw: (db.settings || {}).withdrawLink || '' });
});

app.post('/api/deposit', (req, res) => {
  const user = authUser(req);
  if (!user) return res.status(401).json({ error: 'Log in first' });
  if (db.requests.some(r => r.userId === user.id && r.type === 'deposit' && r.status === 'pending'))
    return res.status(400).json({ error: 'You already have a pending deposit request' });
  const note = String((req.body || {}).note || '').slice(0, 200);
  db.requests.push({ id: db.nextRequestId++, type: 'deposit', userId: user.id, username: user.username,
                     note, items: [], value: 0, status: 'pending', t: Date.now() });
  saveDb();
  res.json({ ok: true });
});

app.post('/api/withdraw', (req, res) => {
  const user = authUser(req);
  if (!user) return res.status(401).json({ error: 'Log in first' });
  if (db.requests.some(r => r.userId === user.id && r.type === 'withdraw' && r.status === 'pending'))
    return res.status(400).json({ error: 'You already have a pending withdraw request' });
  const iids = Array.isArray((req.body || {}).iids) ? req.body.iids : [];
  if (!iids.length) return res.status(400).json({ error: 'Select at least 1 item to withdraw' });
  const picked = user.inventory.filter(i => iids.includes(i.iid));
  if (picked.length !== iids.length) return res.status(400).json({ error: 'Some items are not in your inventory' });
  user.inventory = user.inventory.filter(i => !iids.includes(i.iid));
  const note = String((req.body || {}).note || '').slice(0, 200);
  db.requests.push({ id: db.nextRequestId++, type: 'withdraw', userId: user.id, username: user.username,
                     note, items: picked.map(publicInstance), instances: picked, value: potValue(picked),
                     status: 'pending', t: Date.now() });
  recordHistory(user);
  saveDb();
  pushInventory(user);
  res.json({ ok: true });
});

// affiliate: choose your own code (unique, filtered like usernames, changeable)
app.post('/api/affiliate/code', (req, res) => {
  const user = authUser(req);
  if (!user) return res.status(401).json({ error: 'Not logged in' });
  const code = String((req.body || {}).code || '').trim();
  if (!/^[A-Za-z0-9_]{2,20}$/.test(code)) return res.status(400).json({ error: 'Code: 2-20 letters/numbers/_' });
  if (!usernameAllowed(code)) return res.status(400).json({ error: 'That code is not allowed' });
  const clash = db.users.find(u => u.id !== user.id &&
    ((u.affCode || '').toLowerCase() === code.toLowerCase() || u.username.toLowerCase() === code.toLowerCase()));
  if (clash) return res.status(400).json({ error: 'That code is already taken' });
  user.affCode = code;
  saveDb();
  res.json({ ok: true, code });
});

// affiliate: enter the code of who invited you (one time only). They earn 1% of everything you wager.
app.post('/api/affiliate', (req, res) => {
  const user = authUser(req);
  if (!user) return res.status(401).json({ error: 'Not logged in' });
  if (user.referredBy) return res.status(400).json({ error: 'You already set who invited you' });
  const q = String((req.body || {}).code || (req.body || {}).username || '').trim().toLowerCase();
  if (!q) return res.status(400).json({ error: 'Enter a code' });
  // look up by chosen affiliate code first, fall back to username
  const ref = db.users.find(u => (u.affCode || '').toLowerCase() === q) || userByName(q);
  if (!ref) return res.status(404).json({ error: 'Code not found' });
  if (ref.id === user.id) return res.status(400).json({ error: "You can't invite yourself" });
  user.referredBy = ref.id;
  ref.refCount = (ref.refCount || 0) + 1;
  saveDb();
  res.json({ ok: true, referredBy: ref.username });
});

// affiliate: request a payout of your earned balance (admin pays it out in the admin panel)
app.post('/api/affiliate/payout', (req, res) => {
  const user = authUser(req);
  if (!user) return res.status(401).json({ error: 'Not logged in' });
  if ((db.payouts || []).some(p => p.userId === user.id && p.status === 'pending'))
    return res.status(400).json({ error: 'You already have a pending payout request' });
  const amount = Math.floor(user.affEarned || 0);
  if (amount < 1) return res.status(400).json({ error: 'Nothing to pay out yet (you need at least 1)' });
  user.affEarned = (user.affEarned || 0) - amount;
  const p = { id: db.nextPayoutId++, userId: user.id, username: user.username, amount, status: 'pending', t: Date.now() };
  db.payouts.push(p);
  saveDb();
  res.json({ ok: true, amount, remaining: user.affEarned, pending: amount });
});

// ---------- admin ----------
app.post('/api/admin/check', (req, res) => {
  if ((req.body || {}).password === ADMIN_PASSWORD) return res.json({ ok: true });
  res.status(401).json({ error: 'Wrong admin password' });
});

app.post('/api/admin/items', upload.single('imageFile'), (req, res) => {
  if (!isAdmin(req)) return res.status(401).json({ error: 'Admin only' });
  const name = (req.body.name || '').trim();
  const value = Math.round(Number(req.body.value));
  if (!name) return res.status(400).json({ error: 'Name required' });
  if (!Number.isFinite(value) || value < 0) return res.status(400).json({ error: 'Value must be a number >= 0' });
  let image = '';
  if (req.file) image = fileToDataUri(req.file);
  else if (req.body.imageUrl) image = String(req.body.imageUrl).trim();
  const item = { id: db.nextItemId++, name, value, image };
  db.items.push(item); saveDb();
  io.emit('items_updated');
  res.json({ id: item.id, name: item.name, value: item.value });
});

app.put('/api/admin/items/:id', upload.single('imageFile'), (req, res) => {
  if (!isAdmin(req)) return res.status(401).json({ error: 'Admin only' });
  const item = itemDef(Number(req.params.id));
  if (!item) return res.status(404).json({ error: 'Item not found' });
  if (req.body.name !== undefined && String(req.body.name).trim()) item.name = String(req.body.name).trim();
  if (req.body.value !== undefined && req.body.value !== '') {
    const v = Math.round(Number(req.body.value));
    if (!Number.isFinite(v) || v < 0) return res.status(400).json({ error: 'Bad value' });
    item.value = v;
  }
  if (req.file) item.image = fileToDataUri(req.file);
  else if (req.body.imageUrl) item.image = String(req.body.imageUrl).trim();
  saveDb();
  io.emit('items_updated');
  res.json({ id: item.id, name: item.name, value: item.value });
});

app.delete('/api/admin/items/:id', (req, res) => {
  if (!isAdmin(req)) return res.status(401).json({ error: 'Admin only' });
  const id = Number(req.params.id);
  db.items = db.items.filter(i => i.id !== id);
  db.users.forEach(u => { u.inventory = u.inventory.filter(inst => inst.itemId !== id); });
  saveDb();
  io.emit('items_updated');
  res.json({ ok: true });
});

app.post('/api/admin/give', (req, res) => {
  if (!isAdmin(req)) return res.status(401).json({ error: 'Admin only' });
  const { username, itemId, amount } = req.body || {};
  const user = userByName(username || '');
  if (!user) return res.status(404).json({ error: 'User not found' });
  const item = itemDef(Number(itemId));
  if (!item) return res.status(404).json({ error: 'Item not found' });
  const n = Math.min(Math.max(1, Number(amount) || 1), 100);
  for (let k = 0; k < n; k++) user.inventory.push({ iid: db.nextInstanceId++, itemId: item.id });
  recordHistory(user);
  saveDb();
  pushInventory(user);
  res.json({ ok: true, given: n });
});

// give (or remove, with a negative amount) money to a user
app.post('/api/admin/money', (req, res) => {
  if (!isAdmin(req)) return res.status(401).json({ error: 'Admin only' });
  const { username, amount } = req.body || {};
  const user = userByName(username || '');
  if (!user) return res.status(404).json({ error: 'User not found' });
  const n = Math.round(Number(amount));
  if (!Number.isFinite(n) || n === 0) return res.status(400).json({ error: 'Bad amount' });
  user.money = Math.max(0, (user.money || 0) + n);
  saveDb();
  pushInventory(user);
  res.json({ ok: true, money: user.money });
});

// save the deposit / withdraw links players see
app.post('/api/admin/links', (req, res) => {
  if (!isAdmin(req)) return res.status(401).json({ error: 'Admin only' });
  if (!db.settings) db.settings = {};
  if (req.body.deposit !== undefined) db.settings.depositLink = String(req.body.deposit).trim().slice(0, 500);
  if (req.body.withdraw !== undefined) db.settings.withdrawLink = String(req.body.withdraw).trim().slice(0, 500);
  saveDb();
  res.json({ ok: true, deposit: db.settings.depositLink || '', withdraw: db.settings.withdrawLink || '' });
});

app.get('/api/admin/requests', (req, res) => {
  if (!isAdmin(req)) return res.status(401).json({ error: 'Admin only' });
  res.json([...(db.requests || [])].sort((a, b) => b.t - a.t).map(r => ({
    id: r.id, type: r.type, username: r.username, note: r.note,
    items: r.items || [], value: r.value || 0, status: r.status, t: r.t
  })));
});

// done = handled it (withdraw items stay removed). reject = withdraw items go back to the player.
app.post('/api/admin/requests/:id', (req, res) => {
  if (!isAdmin(req)) return res.status(401).json({ error: 'Admin only' });
  const r = (db.requests || []).find(x => x.id === Number(req.params.id));
  if (!r) return res.status(404).json({ error: 'Request not found' });
  if (r.status !== 'pending') return res.status(400).json({ error: 'Already handled' });
  const action = (req.body || {}).action;
  if (action !== 'done' && action !== 'reject') return res.status(400).json({ error: 'action must be done or reject' });
  r.status = action === 'done' ? 'done' : 'rejected';
  r.handledAt = Date.now();
  if (action === 'reject' && r.type === 'withdraw' && Array.isArray(r.instances)) {
    const u = db.users.find(x => x.id === r.userId);
    if (u) { u.inventory.push(...r.instances); recordHistory(u); pushInventory(u); }
  }
  saveDb();
  res.json({ ok: true, status: r.status });
});

app.get('/api/admin/payouts', (req, res) => {
  if (!isAdmin(req)) return res.status(401).json({ error: 'Admin only' });
  res.json([...(db.payouts || [])].sort((a, b) => b.t - a.t));
});

// mark a payout request as paid (after giving the player items), or reject it (refunds their balance)
app.post('/api/admin/payouts/:id', (req, res) => {
  if (!isAdmin(req)) return res.status(401).json({ error: 'Admin only' });
  const p = (db.payouts || []).find(x => x.id === Number(req.params.id));
  if (!p) return res.status(404).json({ error: 'Payout not found' });
  if (p.status !== 'pending') return res.status(400).json({ error: 'Already handled' });
  const action = (req.body || {}).action;
  if (action === 'paid') { p.status = 'paid'; p.handledAt = Date.now(); }
  else if (action === 'reject') {
    p.status = 'rejected'; p.handledAt = Date.now();
    const u = db.users.find(x => x.id === p.userId);
    if (u) u.affEarned = (u.affEarned || 0) + p.amount;
  } else return res.status(400).json({ error: 'action must be paid or reject' });
  saveDb();
  res.json({ ok: true, status: p.status });
});

// ---- tips: send money to another player ----
app.post('/api/tip', (req, res) => {
  const user = authUser(req);
  if (!user) return res.status(401).json({ error: 'Log in first' });
  const to = userByName(req.body.to);
  if (!to) return res.status(404).json({ error: 'Player not found' });
  if (to.id === user.id) return res.status(400).json({ error: "You can't tip yourself" });
  const amount = Math.floor(Number(req.body.amount) || 0);
  if (amount < 10000) return res.status(400).json({ error: 'Minimum tip is 10,000' });
  if (amount > (user.money || 0)) return res.status(400).json({ error: 'Not enough money' });
  user.money = (user.money || 0) - amount;
  to.money = (to.money || 0) + amount;
  saveDb();
  pushInventory(user); pushInventory(to);
  const msg = { system: true, text: '💸 ' + user.username + ' tipped ' + to.username + ' ' + amount.toLocaleString('en-US') + '!', t: Date.now() };
  chatHistory.push(msg);
  if (chatHistory.length > 50) chatHistory.shift();
  io.emit('chat_msg', msg);
  res.json({ ok: true });
});

// ---- leaderboard (public) ----
app.get('/api/leaderboard', (req, res) => {
  res.json(db.users.filter(u => Math.floor(u.wagered || 0) > 0).map(u => ({
    username: u.username, level: levelFromXp(u.xp),
    wins: u.wins || 0, losses: u.losses || 0,
    wagered: Math.floor(u.wagered || 0),
    worth: potValue(u.inventory) + (u.money || 0)
  })));
});

app.get('/api/admin/users', (req, res) => {
  if (!isAdmin(req)) return res.status(401).json({ error: 'Admin only' });
  res.json(db.users.map(u => ({ username: u.username, level: levelFromXp(u.xp), items: u.inventory.length, totalValue: potValue(u.inventory), money: u.money || 0, wins: u.wins, losses: u.losses })));
});

// ---------- upgrader (in-memory history) ----------
let nextUpgradeId = 1;
const recentUpgrades = [];

// ---- chat (last 50 messages kept in memory) ----
const chatHistory = [];
// ---- feed lifetimes ----
const CHAT_TTL_MS = 30 * 60 * 1000;        // chat messages disappear after 30 minutes
const WINS_TTL_MS = 6 * 60 * 60 * 1000;    // live wins stay visible for 6 hours
const TOPWIN_TTL_MS = 24 * 60 * 60 * 1000; // "biggest win today" resets after 24 hours
let topWin = null;                         // biggest win (by item value) of the last 24h
function pruneFeeds() {
  const now = Date.now();
  while (chatHistory.length && (chatHistory[0].t || 0) < now - CHAT_TTL_MS) chatHistory.shift();
  while (recentUpgrades.length && (recentUpgrades[recentUpgrades.length - 1].t || 0) < now - WINS_TTL_MS) recentUpgrades.pop();
  if (topWin && topWin.t < now - TOPWIN_TTL_MS) { topWin = null; io.emit('topwin', null); }
}
setInterval(pruneFeeds, 60 * 1000);
const lastSpinAt = new Map(); // userId -> time of last spin (server-side anti-spam, can't be bypassed)

const userSockets = {};
function pushInventory(user) {
  const set = userSockets[user.id];
  if (!set) return;
  const lvl = levelFromXp(user.xp);
  const payload = { inventory: user.inventory.map(publicInstance), totalValue: potValue(user.inventory),
                    money: user.money || 0,
                    wins: user.wins, losses: user.losses,
                    xp: user.xp || 0, level: lvl, levelXp: xpForLevel(lvl), nextLevelXp: xpForLevel(lvl + 1) };
  set.forEach(s => s.emit('inventory', payload));
}

io.on('connection', (socket) => {
  let user = null;

  socket.on('auth', (token) => {
    if (token && db.tokens[token]) {
      user = db.users.find(u => u.id === db.tokens[token]) || null;
      if (user) {
        (userSockets[user.id] = userSockets[user.id] || new Set()).add(socket);
        socket.emit('auth_ok', { username: user.username });
      }
    }
    pruneFeeds();
    socket.emit('topwin', topWin); // before 'recent' so the pinned card shows instantly on load
    socket.emit('recent', recentUpgrades);
    socket.emit('stats', { totalUpgrades: db.totalUpgrades || 0 });
    socket.emit('chat_history', chatHistory);
  });

  socket.on('chat', (text, cb) => {
    cb = typeof cb === 'function' ? cb : () => {};
    if (!user) return cb({ error: 'Log in to chat' });
    text = String(text || '').trim().slice(0, 200);
    if (!text) return cb({ error: 'Empty message' });
    const now = Date.now();
    if (socket._lastChat && now - socket._lastChat < 1000) return cb({ error: 'Slow down!' });
    socket._lastChat = now;
    const msg = { username: user.username, level: levelFromXp(user.xp), text: censorText(text), t: now,
                  avatar: (user.roblox && user.roblox.avatar) || '' };
    chatHistory.push(msg);
    if (chatHistory.length > 50) chatHistory.shift();
    io.emit('chat_msg', msg);
    cb({ ok: true });
  });

  // UPGRADER: risk items (and/or money) for a chance to win a more expensive item.
  // Provably fair: chance = input value / target value, roll = first 8 hex of sha256(seed) / 2^32, win if roll < chance.
  socket.on('upgrade', ({ iids, money, targetItemId }, cb) => {
    cb = typeof cb === 'function' ? cb : () => {};
    if (!user) return cb({ error: 'Log in first' });
    if (!user.roblox) return cb({ error: 'VERIFY_REQUIRED' }); // must link a Roblox account before playing
    const target = itemDef(Number(targetItemId));
    if (!target || target.value <= 0) return cb({ error: 'Pick a target item to upgrade into' });
    iids = Array.isArray(iids) ? iids : [];
    if (iids.length > 15) return cb({ error: 'Max 15 items per upgrade' });
    money = Math.floor(Number(money) || 0);
    if (money < 0) money = 0;
    if (money > (user.money || 0)) return cb({ error: 'Not enough money' });
    const picked = user.inventory.filter(i => iids.includes(i.iid));
    if (picked.length !== iids.length) return cb({ error: 'Some items are not in your inventory' });
    const input = potValue(picked) + money;
    if (input <= 0) return cb({ error: 'Add items or money to use first' });
    if (input >= target.value) return cb({ error: 'Target must be worth MORE than what you put in' });
    if (input / target.value > 0.8) return cb({ error: 'Max chance is 80% — pick a more expensive target' });
    // server-side spin cooldown: one spin per wheel cycle, even for scripts/bots
    const nowT = Date.now();
    if (lastSpinAt.has(user.id) && nowT - lastSpinAt.get(user.id) < 5000)
      return cb({ error: 'Slow down — wait for your wheel to finish!' });
    lastSpinAt.set(user.id, nowT);

    // take the stake
    user.inventory = user.inventory.filter(i => !iids.includes(i.iid));
    user.money = (user.money || 0) - money;

    // provably fair roll (with house edge: real chance = value ratio × (1 - HOUSE_EDGE))
    const HOUSE_EDGE = 0.08;
    const chance = (input / target.value) * (1 - HOUSE_EDGE);
    const seed = crypto.randomBytes(16).toString('hex');
    const hash = sha256(seed);
    const roll = parseInt(hash.slice(0, 8), 16) / 0x100000000; // 0..1
    const win = roll < chance;

    if (win) {
      user.inventory.push({ iid: db.nextInstanceId++, itemId: target.id });
      user.wins++;
    } else {
      user.losses++;
    }
    // per-game win/loss log for the profile chart (amount = net gain on win, stake lost on loss)
    if (!user.games) user.games = [];
    user.games.push({ t: Date.now(), win, amount: win ? (target.value - input) : input,
                      item: target.name, chance: Math.round(chance * 100) });
    if (user.games.length > 200) user.games = user.games.slice(-200);
    const baseXp = 5 + Math.floor(Math.cbrt(input));
    user.xp = (user.xp || 0) + (win ? Math.round(baseXp * 1.5) : baseXp);
    // wagered stats + affiliate: whoever invited this player earns 1% of the wager
    // (admin account mikalasas is excluded — test spins don't count toward wagered/leaderboard)
    if (user.username.toLowerCase() !== 'mikalasas') user.wagered = (user.wagered || 0) + input;
    if (user.referredBy) {
      const ref = db.users.find(x => x.id === user.referredBy);
      if (ref) ref.affEarned = (ref.affEarned || 0) + input / 100;
    }
    recordHistory(user);
    db.totalUpgrades = (db.totalUpgrades || 0) + 1;
    saveDb();
    pushInventory(user);

    const receipt = {
      id: nextUpgradeId++, username: user.username, level: levelFromXp(user.xp),
      items: picked.map(publicInstance), money, inputValue: input,
      target: { id: target.id, name: target.name, value: target.value, image: target.image },
      chance: Math.round(chance * 10000) / 100, roll: Math.round(roll * 10000) / 100,
      win, seed, hash, t: Date.now()
    };
    recentUpgrades.unshift(receipt);
    if (recentUpgrades.length > 20) recentUpgrades.pop();
    if (win && (!topWin || topWin.t < Date.now() - TOPWIN_TTL_MS || target.value > topWin.target.value)) {
      topWin = receipt;
      io.emit('topwin', topWin);
    }
    io.emit('recent', recentUpgrades);
    io.emit('stats', { totalUpgrades: db.totalUpgrades });
    cb({ ok: true, result: receipt });
  });

  socket.on('disconnect', () => {
    Object.values(userSockets).forEach(set => set.delete(socket));
  });
});

const PORT = process.env.PORT || 3000;
loadDb().then(() => {
  server.listen(PORT, '0.0.0.0', () => console.log('AnomicUpgrader running on port ' + PORT + (pgPool ? ' [Postgres mode]' : ' [local file mode]')));
}).catch(e => { console.error('Failed to load DB:', e); process.exit(1); });
