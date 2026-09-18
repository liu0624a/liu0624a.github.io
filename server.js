/*
 * VehicleWatch MVP server. It intentionally uses only Node built-ins so it can
 * run in a fresh environment while retaining a real persistent database.
 */
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { URL } = require('node:url');
const { DatabaseSync } = require('node:sqlite');

const ROOT = __dirname;
const PORT = Number(process.env.PORT || 3000);
const SECRET = process.env.APP_SECRET || 'local-development-secret-change-before-deployment';
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const DATA_DIR = path.join(ROOT, 'data');
const UPLOAD_DIR = path.join(ROOT, 'uploads');
const PUBLIC_DIR = path.join(ROOT, 'public');
fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const db = new DatabaseSync(path.join(DATA_DIR, 'vehiclewatch.sqlite'));
db.exec('PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;');

db.exec(`
CREATE TABLE IF NOT EXISTS staff_users (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('Reviewer','Case Manager','Administrator')),
  active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  id INTEGER PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE, user_id INTEGER NOT NULL,
  csrf_token TEXT NOT NULL, expires_at TEXT NOT NULL, created_at TEXT NOT NULL,
  FOREIGN KEY(user_id) REFERENCES staff_users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS locations (
  id INTEGER PRIMARY KEY, address TEXT NOT NULL, latitude REAL, longitude REAL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS vehicle_cases (
  id INTEGER PRIMARY KEY, case_id TEXT NOT NULL UNIQUE, location_id INTEGER,
  plate TEXT, plate_state TEXT, vehicle_make TEXT, vehicle_model TEXT, vehicle_color TEXT, vehicle_type TEXT,
  status TEXT NOT NULL DEFAULT 'New' CHECK(status IN ('New','Under Review','Verified','Action in Progress','Resolved','Archived')),
  resolution_note TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, resolved_at TEXT,
  FOREIGN KEY(location_id) REFERENCES locations(id)
);
CREATE TABLE IF NOT EXISTS reports (
  id INTEGER PRIMARY KEY, report_id TEXT NOT NULL UNIQUE, vehicle_case_id INTEGER, photo_id INTEGER,
  location_id INTEGER NOT NULL, plate TEXT, plate_state TEXT, vehicle_make TEXT, vehicle_model TEXT,
  vehicle_color TEXT, vehicle_type TEXT, description TEXT, observed_at TEXT,
  submitted_at TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'New'
    CHECK(status IN ('New','Under Review','Verified','Rejected','Duplicate','Needs more information','Archived')),
  risk_score INTEGER NOT NULL DEFAULT 0, risk_flags TEXT NOT NULL DEFAULT '[]', reporter_hash TEXT NOT NULL,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  FOREIGN KEY(vehicle_case_id) REFERENCES vehicle_cases(id), FOREIGN KEY(location_id) REFERENCES locations(id)
);
CREATE TABLE IF NOT EXISTS photos (
  id INTEGER PRIMARY KEY, report_id INTEGER NOT NULL, storage_path TEXT NOT NULL, thumbnail_path TEXT,
  file_type TEXT NOT NULL, file_size INTEGER NOT NULL, image_width INTEGER NOT NULL, image_height INTEGER NOT NULL,
  created_at TEXT NOT NULL, FOREIGN KEY(report_id) REFERENCES reports(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS report_notes (
  id INTEGER PRIMARY KEY, report_id INTEGER NOT NULL, staff_user_id INTEGER NOT NULL, note TEXT NOT NULL,
  created_at TEXT NOT NULL, FOREIGN KEY(report_id) REFERENCES reports(id),
  FOREIGN KEY(staff_user_id) REFERENCES staff_users(id)
);
CREATE TABLE IF NOT EXISTS review_history (
  id INTEGER PRIMARY KEY, report_id INTEGER, vehicle_case_id INTEGER, staff_user_id INTEGER,
  action TEXT NOT NULL, previous_status TEXT, new_status TEXT, notes TEXT, created_at TEXT NOT NULL,
  FOREIGN KEY(report_id) REFERENCES reports(id), FOREIGN KEY(vehicle_case_id) REFERENCES vehicle_cases(id),
  FOREIGN KEY(staff_user_id) REFERENCES staff_users(id)
);
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY, actor_type TEXT NOT NULL, actor_id TEXT, action TEXT NOT NULL,
  entity_type TEXT NOT NULL, entity_id TEXT NOT NULL, metadata TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS rate_limits (
  id INTEGER PRIMARY KEY, source_hash TEXT NOT NULL, action TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status, submitted_at DESC);
CREATE INDEX IF NOT EXISTS idx_reports_plate ON reports(plate);
CREATE INDEX IF NOT EXISTS idx_cases_status ON vehicle_cases(status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_rate_source ON rate_limits(source_hash, action, created_at);
`);

const now = () => new Date().toISOString();
const idDate = () => new Date().getUTCFullYear();
const clean = (value, max = 280) => String(value || '').trim().replace(/[<>]/g, '').slice(0, max);
const normalizePlate = (value) => clean(value, 16).toUpperCase().replace(/[^A-Z0-9]/g, '');
const hash = (value) => crypto.createHash('sha256').update(String(value)).digest('hex');
const sourceHash = (req) => hash(`${SECRET}:${req.socket.remoteAddress || 'unknown'}`);
const validReportStatus = new Set(['New', 'Under Review', 'Verified', 'Rejected', 'Duplicate', 'Needs more information', 'Archived']);
const validCaseStatus = new Set(['New', 'Under Review', 'Verified', 'Action in Progress', 'Resolved', 'Archived']);

function passwordHash(password, salt = crypto.randomBytes(16).toString('hex')) {
  return `${salt}:${crypto.pbkdf2Sync(password, salt, 160000, 32, 'sha256').toString('hex')}`;
}
function passwordMatches(password, encoded) {
  const [salt, expected] = String(encoded).split(':');
  const actual = crypto.pbkdf2Sync(password, salt, 160000, 32, 'sha256').toString('hex');
  return expected.length === actual.length && crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(actual));
}
function audit(actorType, actorId, action, entityType, entityId, metadata = {}) {
  db.prepare('INSERT INTO audit_log (actor_type,actor_id,action,entity_type,entity_id,metadata,created_at) VALUES (?,?,?,?,?,?,?)')
    .run(actorType, actorId ? String(actorId) : null, action, entityType, String(entityId), JSON.stringify(metadata), now());
}
function addHistory({ reportId = null, caseId = null, userId = null, action, previous = null, next = null, notes = null }) {
  db.prepare('INSERT INTO review_history (report_id,vehicle_case_id,staff_user_id,action,previous_status,new_status,notes,created_at) VALUES (?,?,?,?,?,?,?,?)')
    .run(reportId, caseId, userId, action, previous, next, notes, now());
}
function makeReportId() {
  let value;
  do value = `AV-${idDate()}-${crypto.randomInt(100000, 1000000)}`;
  while (db.prepare('SELECT 1 FROM reports WHERE report_id=?').get(value));
  return value;
}
function makeCaseId() {
  let value;
  do value = `CASE-${idDate()}-${crypto.randomInt(1000, 10000)}`;
  while (db.prepare('SELECT 1 FROM vehicle_cases WHERE case_id=?').get(value));
  return value;
}
function insertLocation(address, latitude, longitude) {
  const result = db.prepare('INSERT INTO locations (address,latitude,longitude,created_at) VALUES (?,?,?,?)')
    .run(address, latitude, longitude, now());
  return Number(result.lastInsertRowid);
}

function seedDemoData() {
  if (db.prepare('SELECT count(*) AS n FROM staff_users').get().n) return;
  const created = now();
  const admin = db.prepare('INSERT INTO staff_users (name,email,password_hash,role,active,created_at) VALUES (?,?,?,?,?,?)')
    .run('Demo Administrator', 'admin@vehiclewatch.local', passwordHash('ChangeMe!2026'), 'Administrator', 1, created);
  const adminId = Number(admin.lastInsertRowid);
  const loc1 = insertLocation('Kīlauea Ave & Keawe St, Hilo, HI', 19.7199, -155.0867);
  const caseResult = db.prepare(`INSERT INTO vehicle_cases (case_id,location_id,plate,plate_state,vehicle_make,vehicle_model,vehicle_color,vehicle_type,status,created_at,updated_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?)`).run('CASE-2026-1042', loc1, 'HILO842', 'HI', 'Toyota', 'Camry', 'Silver', 'Sedan', 'Under Review', created, created);
  const caseDbId = Number(caseResult.lastInsertRowid);
  const loc2 = insertLocation('Kamehameha Ave near Wailoa River, Hilo, HI', 19.7246, -155.0820);
  const r1 = db.prepare(`INSERT INTO reports (report_id,vehicle_case_id,location_id,plate,plate_state,vehicle_make,vehicle_model,vehicle_color,vehicle_type,description,submitted_at,status,risk_score,risk_flags,reporter_hash,created_at,updated_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run('AV-2026-101001', caseDbId, loc1, 'HILO842', 'HI', 'Toyota', 'Camry', 'Silver', 'Sedan', 'Vehicle has been parked for several days.', created, 'Under Review', 0, '[]', 'demo', created, created);
  db.prepare(`INSERT INTO reports (report_id,location_id,plate,plate_state,vehicle_make,vehicle_model,vehicle_color,vehicle_type,description,submitted_at,status,risk_score,risk_flags,reporter_hash,created_at,updated_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run('AV-2026-101002', loc2, 'KONA217', 'HI', 'Ford', 'F-150', 'White', 'Truck', 'Appears abandoned by the roadside.', created, 'New', 5, '["Demo: possible address match"]', 'demo', created, created);
  const r1Id = Number(r1.lastInsertRowid);
  addHistory({ reportId: r1Id, userId: adminId, action: 'Demo report seeded', next: 'Under Review', notes: 'Development/demo record.' });
  audit('system', null, 'Demo data created', 'system', 'seed', { doNotUseInProduction: true });
}
seedDemoData();

function sendJson(res, status, payload, extraHeaders = {}) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store', ...extraHeaders,
  });
  res.end(body);
}
function sendText(res, status, message) { sendJson(res, status, { error: message }); }
function setSecurityHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(self), camera=(self)');
  res.setHeader('Content-Security-Policy', "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");
}
function readJson(req, limit = 7 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > limit) { reject(new Error('Request is too large.')); req.destroy(); return; }
      chunks.push(chunk);
    });
    req.on('end', () => {
      try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {}); }
      catch { reject(new Error('Invalid request data.')); }
    });
    req.on('error', reject);
  });
}
function parseCookies(req) {
  return Object.fromEntries(String(req.headers.cookie || '').split(';').map(v => v.trim()).filter(Boolean).map(v => {
    const i = v.indexOf('='); return [v.slice(0, i), decodeURIComponent(v.slice(i + 1))];
  }));
}
function sessionFor(req) {
  const token = parseCookies(req).vw_session;
  if (!token) return null;
  const session = db.prepare(`SELECT s.*, u.id AS user_id,u.name,u.email,u.role,u.active FROM sessions s
    JOIN staff_users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?`).get(hash(token), now());
  return session && session.active ? session : null;
}
function requireStaff(req, res, roles = null, csrf = false) {
  const session = sessionFor(req);
  if (!session) { sendText(res, 401, 'Please sign in to continue.'); return null; }
  if (roles && !roles.includes(session.role)) { sendText(res, 403, 'Your staff role does not permit that action.'); return null; }
  if (csrf && req.headers['x-csrf-token'] !== session.csrf_token) { sendText(res, 403, 'Your session verification token is invalid. Refresh and try again.'); return null; }
  return session;
}
function clearSession(res) {
  res.setHeader('Set-Cookie', 'vw_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
}
function createSession(res, userId) {
  const token = crypto.randomBytes(32).toString('base64url');
  const csrf = crypto.randomBytes(24).toString('base64url');
  const expires = new Date(Date.now() + 8 * 60 * 60 * 1000).toISOString();
  db.prepare('INSERT INTO sessions (token_hash,user_id,csrf_token,expires_at,created_at) VALUES (?,?,?,?,?)')
    .run(hash(token), userId, csrf, expires, now());
  res.setHeader('Set-Cookie', `vw_session=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800${IS_PRODUCTION ? '; Secure' : ''}`);
  return csrf;
}
function imageInfo(buffer, declaredType) {
  const png = buffer.length > 24 && buffer.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]));
  const jpeg = buffer.length > 4 && buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff;
  const webp = buffer.length > 30 && buffer.subarray(0, 4).toString() === 'RIFF' && buffer.subarray(8, 12).toString() === 'WEBP';
  let type, width, height, ext;
  if (png) { type = 'image/png'; ext = 'png'; width = buffer.readUInt32BE(16); height = buffer.readUInt32BE(20); }
  else if (jpeg) {
    type = 'image/jpeg'; ext = 'jpg'; let p = 2;
    while (p < buffer.length - 9) {
      if (buffer[p] !== 0xff) { p++; continue; }
      while (buffer[p] === 0xff) p++;
      const marker = buffer[p++];
      if (marker === 0xd8 || marker === 0xd9) continue;
      if (p + 2 > buffer.length) break;
      const len = buffer.readUInt16BE(p);
      if (len < 2 || p + len > buffer.length) break;
      if ([0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf].includes(marker)) {
        height = buffer.readUInt16BE(p + 3); width = buffer.readUInt16BE(p + 5); break;
      }
      p += len;
    }
  } else if (webp && buffer.subarray(12, 16).toString() === 'VP8X') {
    type = 'image/webp'; ext = 'webp';
    width = 1 + buffer[24] + (buffer[25] << 8) + (buffer[26] << 16);
    height = 1 + buffer[27] + (buffer[28] << 8) + (buffer[29] << 16);
  } else { throw new Error('Upload a valid JPG, PNG, or WebP image.'); }
  if (declaredType && !declaredType.startsWith('image/')) throw new Error('The uploaded file is not an image.');
  if (!width || !height || width < 120 || height < 120) throw new Error('Use a clear photo at least 120 × 120 pixels.');
  if (width * height > 64_000_000) throw new Error('Image dimensions are too large.');
  return { type, ext, width, height };
}
function decodePhoto(value) {
  const match = /^data:(image\/(?:jpeg|png|webp));base64,([A-Za-z0-9+/=\s]+)$/.exec(String(value || ''));
  if (!match) throw new Error('Add a vehicle photo in JPG, PNG, or WebP format.');
  const buffer = Buffer.from(match[2].replace(/\s/g, ''), 'base64');
  if (buffer.length < 1024 || buffer.length > 5 * 1024 * 1024) throw new Error('Use an image between 1 KB and 5 MB.');
  return { buffer, declaredType: match[1] };
}
function numericLocation(value, name) {
  if (value === '' || value === null || value === undefined) return null;
  const n = Number(value);
  if (!Number.isFinite(n) || (name === 'latitude' && (n < -90 || n > 90)) || (name === 'longitude' && (n < -180 || n > 180))) throw new Error(`Enter a valid ${name}.`);
  return n;
}
function summarizeReport(row) {
  return {
    id: row.id, reportId: row.report_id, caseId: row.case_id || null, submittedAt: row.submitted_at, observedAt: row.observed_at,
    status: row.status, plate: row.plate, plateState: row.plate_state, make: row.vehicle_make, model: row.vehicle_model,
    color: row.vehicle_color, type: row.vehicle_type, description: row.description, address: row.address,
    latitude: row.latitude, longitude: row.longitude, riskScore: row.risk_score, riskFlags: JSON.parse(row.risk_flags || '[]'),
    hasPhoto: Boolean(row.photo_id), photoUrl: row.photo_id ? `/api/staff/photos/${row.photo_id}` : null,
  };
}
function reportRowById(id) {
  return db.prepare(`SELECT r.*, l.address,l.latitude,l.longitude, c.case_id, p.id AS stored_photo_id
    FROM reports r JOIN locations l ON l.id=r.location_id LEFT JOIN vehicle_cases c ON c.id=r.vehicle_case_id
    LEFT JOIN photos p ON p.id=r.photo_id WHERE r.id=?`).get(id);
}
function reportRowByPublicId(reportId) {
  return db.prepare(`SELECT r.*, l.address,l.latitude,l.longitude, c.case_id, p.id AS stored_photo_id
    FROM reports r JOIN locations l ON l.id=r.location_id LEFT JOIN vehicle_cases c ON c.id=r.vehicle_case_id
    LEFT JOIN photos p ON p.id=r.photo_id WHERE r.report_id=?`).get(reportId);
}
function distance(aLat, aLng, bLat, bLng) {
  if (![aLat, aLng, bLat, bLng].every(Number.isFinite)) return Infinity;
  return Math.hypot(aLat - bLat, aLng - bLng);
}
function analyzePossibleDuplicates(report) {
  const candidates = [];
  const rows = db.prepare(`SELECT r.*,l.address,l.latitude,l.longitude,c.case_id FROM reports r
    JOIN locations l ON l.id=r.location_id LEFT JOIN vehicle_cases c ON c.id=r.vehicle_case_id
    WHERE r.id != ? AND r.status NOT IN ('Rejected','Archived') ORDER BY r.submitted_at DESC LIMIT 150`).all(report.id);
  for (const item of rows) {
    let score = 0; const reasons = [];
    if (report.plate && item.plate && report.plate === item.plate) { score += 65; reasons.push('same license plate'); }
    if (report.vehicle_make && item.vehicle_make && report.vehicle_make.toLowerCase() === item.vehicle_make.toLowerCase()) { score += 10; reasons.push('same make'); }
    if (report.vehicle_color && item.vehicle_color && report.vehicle_color.toLowerCase() === item.vehicle_color.toLowerCase()) { score += 5; reasons.push('same color'); }
    const d = distance(report.latitude, report.longitude, item.latitude, item.longitude);
    if (d < 0.015) { score += 30; reasons.push('nearby location'); }
    else if (report.address && item.address && report.address.toLowerCase() === item.address.toLowerCase()) { score += 25; reasons.push('same address'); }
    if (score >= 30) candidates.push({ kind: 'report', id: item.id, publicId: item.report_id, caseId: item.case_id || null, score: Math.min(score, 99), reasons });
  }
  const cases = db.prepare(`SELECT c.*,l.address,l.latitude,l.longitude FROM vehicle_cases c LEFT JOIN locations l ON l.id=c.location_id
    WHERE c.status NOT IN ('Resolved','Archived') ORDER BY c.updated_at DESC LIMIT 150`).all();
  for (const item of cases) {
    let score = 0; const reasons = [];
    if (report.plate && item.plate && report.plate === item.plate) { score += 70; reasons.push('same license plate'); }
    if (report.vehicle_make && item.vehicle_make && report.vehicle_make.toLowerCase() === item.vehicle_make.toLowerCase()) { score += 10; reasons.push('same make'); }
    if (distance(report.latitude, report.longitude, item.latitude, item.longitude) < 0.015) { score += 28; reasons.push('nearby location'); }
    if (score >= 30) candidates.push({ kind: 'case', id: item.id, publicId: item.case_id, score: Math.min(score, 99), reasons });
  }
  return candidates.sort((a, b) => b.score - a.score).slice(0, 8);
}
function staffUser(session) { return { id: session.user_id, name: session.name, email: session.email, role: session.role }; }

function serveFile(res, filePath) {
  if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) { sendText(res, 404, 'Not found.'); return; }
  const ext = path.extname(filePath).toLowerCase();
  const types = { '.html': 'text/html; charset=utf-8', '.js': 'application/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.ico': 'image/x-icon' };
  res.writeHead(200, { 'Content-Type': types[ext] || 'application/octet-stream', 'Cache-Control': ext === '.html' ? 'no-cache' : 'public, max-age=3600' });
  fs.createReadStream(filePath).pipe(res);
}
function servePrivatePhoto(req, res, photoId) {
  if (!requireStaff(req, res)) return;
  const photo = db.prepare('SELECT * FROM photos WHERE id=?').get(photoId);
  if (!photo) return sendText(res, 404, 'Photo not found.');
  const file = path.join(UPLOAD_DIR, path.basename(photo.storage_path));
  if (!fs.existsSync(file)) return sendText(res, 404, 'Photo file is unavailable.');
  res.writeHead(200, { 'Content-Type': photo.file_type, 'Cache-Control': 'private, no-store' });
  fs.createReadStream(file).pipe(res);
}

async function publicSubmit(req, res) {
  let body;
  try { body = await readJson(req); } catch (error) { return sendText(res, 400, error.message); }
  const source = sourceHash(req);
  const since = new Date(Date.now() - 60 * 60 * 1000).toISOString();
  const recent = db.prepare('SELECT count(*) AS count FROM rate_limits WHERE source_hash=? AND action=? AND created_at>?').get(source, 'public_submit', since).count;
  if (recent >= 5) return sendText(res, 429, 'Too many reports were submitted from this connection. Please try again later.');
  if (clean(body.website, 80) || Number(body.startedAt || 0) > Date.now() || Date.now() - Number(body.startedAt || 0) < 800) return sendText(res, 400, 'We could not verify this submission. Please complete the form and try again.');
  try {
    const address = clean(body.address, 320);
    if (address.length < 5) throw new Error('Enter the vehicle location or a nearby address.');
    const latitude = numericLocation(body.latitude, 'latitude');
    const longitude = numericLocation(body.longitude, 'longitude');
    if ((latitude === null) !== (longitude === null)) throw new Error('Enter both latitude and longitude, or leave both blank.');
    const photo = decodePhoto(body.photoData);
    const image = imageInfo(photo.buffer, photo.declaredType);
    const plate = normalizePlate(body.plate);
    const plateState = clean(body.plateState, 24).toUpperCase();
    const make = clean(body.make, 60);
    const model = clean(body.model, 60);
    const color = clean(body.color, 40);
    const vehicleType = clean(body.vehicleType, 40);
    const description = clean(body.description, 1200);
    if (!plate && !make && !model && !description) throw new Error('Add at least one identifying vehicle detail or a short description.');
    const riskFlags = [];
    if (recent >= 2) riskFlags.push('Repeated submissions from this source');
    const duplicateProbe = { id: -1, plate, vehicle_make: make, vehicle_color: color, address, latitude, longitude };
    const similar = analyzePossibleDuplicates(duplicateProbe);
    if (similar.length) riskFlags.push('Possible duplicate match');
    const locationId = insertLocation(address, latitude, longitude);
    const submittedAt = now(); const reportId = makeReportId();
    const result = db.prepare(`INSERT INTO reports (report_id,location_id,plate,plate_state,vehicle_make,vehicle_model,vehicle_color,vehicle_type,description,observed_at,submitted_at,status,risk_score,risk_flags,reporter_hash,created_at,updated_at)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(reportId, locationId, plate || null, plateState || null, make || null, model || null, color || null, vehicleType || null, description || null,
      body.observedAt ? new Date(body.observedAt).toISOString() : null, submittedAt, 'New', Math.min(100, riskFlags.length * 25), JSON.stringify(riskFlags), source, submittedAt, submittedAt);
    const reportDbId = Number(result.lastInsertRowid);
    const fileName = `${crypto.randomUUID()}.${image.ext}`;
    fs.writeFileSync(path.join(UPLOAD_DIR, fileName), photo.buffer, { mode: 0o600 });
    const photoId = Number(db.prepare('INSERT INTO photos (report_id,storage_path,thumbnail_path,file_type,file_size,image_width,image_height,created_at) VALUES (?,?,?,?,?,?,?,?)')
      .run(reportDbId, fileName, fileName, image.type, photo.buffer.length, image.width, image.height, submittedAt).lastInsertRowid);
    db.prepare('UPDATE reports SET photo_id=? WHERE id=?').run(photoId, reportDbId);
    db.prepare('INSERT INTO rate_limits (source_hash,action,created_at) VALUES (?,?,?)').run(source, 'public_submit', submittedAt);
    audit('public', source.slice(0, 12), 'Report created', 'report', reportId, { riskFlags });
    return sendJson(res, 201, { reportId, status: 'New', submittedAt, message: 'Your report was received and is awaiting review.' });
  } catch (error) { return sendText(res, 400, error.message || 'We could not submit your report.'); }
}

async function staffLogin(req, res) {
  let body; try { body = await readJson(req, 128 * 1024); } catch (error) { return sendText(res, 400, error.message); }
  const email = clean(body.email, 160).toLowerCase();
  const user = db.prepare('SELECT * FROM staff_users WHERE email=? AND active=1').get(email);
  if (!user || !passwordMatches(String(body.password || ''), user.password_hash)) {
    audit('unknown', email || null, 'Failed sign-in', 'staff_auth', email || 'unknown');
    return sendText(res, 401, 'Email or password is incorrect.');
  }
  const csrfToken = createSession(res, user.id);
  audit('staff', user.id, 'Signed in', 'staff_user', user.id);
  return sendJson(res, 200, { user: { id: user.id, name: user.name, email: user.email, role: user.role }, csrfToken });
}
function dashboard(req, res) {
  const session = requireStaff(req, res); if (!session) return;
  const counts = {
    newReports: db.prepare("SELECT count(*) AS n FROM reports WHERE status='New'").get().n,
    reviewQueue: db.prepare("SELECT count(*) AS n FROM reports WHERE status IN ('New','Under Review','Needs more information')").get().n,
    possibleDuplicates: db.prepare("SELECT count(*) AS n FROM reports WHERE risk_flags LIKE '%Possible duplicate%'").get().n,
    activeCases: db.prepare("SELECT count(*) AS n FROM vehicle_cases WHERE status NOT IN ('Resolved','Archived')").get().n,
    resolvedThisMonth: db.prepare("SELECT count(*) AS n FROM vehicle_cases WHERE status='Resolved' AND resolved_at >= ?").get(new Date(new Date().getFullYear(), new Date().getMonth(), 1).toISOString()).n,
  };
  const recent = db.prepare(`SELECT r.*,l.address,l.latitude,l.longitude,c.case_id FROM reports r JOIN locations l ON l.id=r.location_id LEFT JOIN vehicle_cases c ON c.id=r.vehicle_case_id ORDER BY r.submitted_at DESC LIMIT 8`).all().map(summarizeReport);
  const mapCases = db.prepare(`SELECT c.case_id,c.status,c.vehicle_make,c.vehicle_model,c.vehicle_color,l.address,l.latitude,l.longitude FROM vehicle_cases c LEFT JOIN locations l ON l.id=c.location_id WHERE c.status NOT IN ('Resolved','Archived') ORDER BY c.updated_at DESC LIMIT 30`).all();
  sendJson(res, 200, { user: staffUser(session), counts, recent, mapCases });
}
function listReports(req, res, url) {
  if (!requireStaff(req, res)) return;
  const q = clean(url.searchParams.get('q'), 100); const status = clean(url.searchParams.get('status'), 40); const page = Math.max(1, Number(url.searchParams.get('page') || 1)); const limit = 30; const values = []; const where = [];
  if (status && validReportStatus.has(status)) { where.push('r.status=?'); values.push(status); }
  if (q) { where.push('(r.report_id LIKE ? OR c.case_id LIKE ? OR r.plate LIKE ? OR r.vehicle_make LIKE ? OR r.vehicle_model LIKE ? OR l.address LIKE ?)'); for (let i = 0; i < 6; i++) values.push(`%${q}%`); }
  const condition = where.length ? `WHERE ${where.join(' AND ')}` : '';
  const total = db.prepare(`SELECT count(*) AS n FROM reports r JOIN locations l ON l.id=r.location_id LEFT JOIN vehicle_cases c ON c.id=r.vehicle_case_id ${condition}`).get(...values).n;
  const rows = db.prepare(`SELECT r.*,l.address,l.latitude,l.longitude,c.case_id FROM reports r JOIN locations l ON l.id=r.location_id LEFT JOIN vehicle_cases c ON c.id=r.vehicle_case_id ${condition} ORDER BY r.submitted_at DESC LIMIT ? OFFSET ?`).all(...values, limit, (page - 1) * limit).map(summarizeReport);
  sendJson(res, 200, { rows, total, page, pages: Math.max(1, Math.ceil(total / limit)) });
}
function reportDetail(req, res, reportId) {
  if (!requireStaff(req, res)) return;
  const row = reportRowById(reportId); if (!row) return sendText(res, 404, 'Report not found.');
  const report = summarizeReport(row);
  const notes = db.prepare(`SELECT n.*,u.name,u.role FROM report_notes n JOIN staff_users u ON u.id=n.staff_user_id WHERE n.report_id=? ORDER BY n.created_at DESC`).all(reportId);
  const history = db.prepare(`SELECT h.*,u.name FROM review_history h LEFT JOIN staff_users u ON u.id=h.staff_user_id WHERE h.report_id=? ORDER BY h.created_at DESC`).all(reportId);
  sendJson(res, 200, { report, notes, history, duplicates: analyzePossibleDuplicates(row) });
}
async function updateReport(req, res, reportId) {
  const session = requireStaff(req, res, ['Reviewer', 'Case Manager', 'Administrator'], true); if (!session) return;
  let body; try { body = await readJson(req, 256 * 1024); } catch (error) { return sendText(res, 400, error.message); }
  const row = reportRowById(reportId); if (!row) return sendText(res, 404, 'Report not found.');
  const next = clean(body.status, 40);
  if (!validReportStatus.has(next)) return sendText(res, 400, 'Choose a valid report status.');
  const note = clean(body.note, 1200);
  db.prepare('UPDATE reports SET status=?,updated_at=? WHERE id=?').run(next, now(), reportId);
  addHistory({ reportId, userId: session.user_id, action: 'Report status changed', previous: row.status, next, notes: note || null });
  audit('staff', session.user_id, 'Report status changed', 'report', row.report_id, { previous: row.status, next, note });
  sendJson(res, 200, { ok: true, status: next });
}
async function addNote(req, res, reportId) {
  const session = requireStaff(req, res, ['Reviewer', 'Case Manager', 'Administrator'], true); if (!session) return;
  let body; try { body = await readJson(req, 128 * 1024); } catch (error) { return sendText(res, 400, error.message); }
  const row = reportRowById(reportId); const note = clean(body.note, 1600);
  if (!row) return sendText(res, 404, 'Report not found.'); if (note.length < 2) return sendText(res, 400, 'Enter a staff note.');
  db.prepare('INSERT INTO report_notes (report_id,staff_user_id,note,created_at) VALUES (?,?,?,?)').run(reportId, session.user_id, note, now());
  addHistory({ reportId, userId: session.user_id, action: 'Staff note added', notes: note });
  audit('staff', session.user_id, 'Staff note added', 'report', row.report_id);
  sendJson(res, 201, { ok: true });
}
async function createOrLinkCase(req, res, reportId) {
  const session = requireStaff(req, res, ['Case Manager', 'Administrator'], true); if (!session) return;
  let body; try { body = await readJson(req, 128 * 1024); } catch (error) { return sendText(res, 400, error.message); }
  const report = reportRowById(reportId); if (!report) return sendText(res, 404, 'Report not found.');
  let caseRow; let action;
  if (body.existingCaseId) {
    caseRow = db.prepare('SELECT * FROM vehicle_cases WHERE case_id=?').get(clean(body.existingCaseId, 32));
    if (!caseRow) return sendText(res, 404, 'That vehicle case was not found.');
    action = 'Linked to existing vehicle case';
  } else {
    const locationId = report.location_id;
    const caseId = makeCaseId();
    const result = db.prepare(`INSERT INTO vehicle_cases (case_id,location_id,plate,plate_state,vehicle_make,vehicle_model,vehicle_color,vehicle_type,status,created_at,updated_at)
      VALUES (?,?,?,?,?,?,?,?,?,?,?)`).run(caseId, locationId, report.plate, report.plate_state, report.vehicle_make, report.vehicle_model, report.vehicle_color, report.vehicle_type, 'New', now(), now());
    caseRow = db.prepare('SELECT * FROM vehicle_cases WHERE id=?').get(Number(result.lastInsertRowid));
    action = 'Created and linked vehicle case';
    addHistory({ caseId: caseRow.id, userId: session.user_id, action: 'Vehicle case created', next: 'New' });
    audit('staff', session.user_id, 'Vehicle case created', 'vehicle_case', caseRow.case_id, { reportId: report.report_id });
  }
  db.prepare('UPDATE reports SET vehicle_case_id=?,updated_at=? WHERE id=?').run(caseRow.id, now(), reportId);
  addHistory({ reportId, caseId: caseRow.id, userId: session.user_id, action, notes: clean(body.note, 600) || null });
  audit('staff', session.user_id, action, 'report', report.report_id, { caseId: caseRow.case_id });
  sendJson(res, 200, { ok: true, caseId: caseRow.case_id });
}
function listCases(req, res, url) {
  if (!requireStaff(req, res)) return;
  const q = clean(url.searchParams.get('q'), 100); const status = clean(url.searchParams.get('status'), 40); const values = []; const where = [];
  if (status && validCaseStatus.has(status)) { where.push('c.status=?'); values.push(status); }
  if (q) { where.push('(c.case_id LIKE ? OR c.plate LIKE ? OR c.vehicle_make LIKE ? OR c.vehicle_model LIKE ? OR l.address LIKE ?)'); for (let i = 0; i < 5; i++) values.push(`%${q}%`); }
  const condition = where.length ? `WHERE ${where.join(' AND ')}` : '';
  const rows = db.prepare(`SELECT c.*,l.address,l.latitude,l.longitude,count(r.id) AS report_count FROM vehicle_cases c LEFT JOIN locations l ON l.id=c.location_id LEFT JOIN reports r ON r.vehicle_case_id=c.id ${condition} GROUP BY c.id ORDER BY c.updated_at DESC`).all(...values);
  sendJson(res, 200, { rows });
}
function caseDetail(req, res, caseId) {
  if (!requireStaff(req, res)) return;
  const item = db.prepare(`SELECT c.*,l.address,l.latitude,l.longitude FROM vehicle_cases c LEFT JOIN locations l ON l.id=c.location_id WHERE c.id=?`).get(caseId);
  if (!item) return sendText(res, 404, 'Vehicle case not found.');
  const reports = db.prepare(`SELECT r.*,l.address,l.latitude,l.longitude,c.case_id FROM reports r JOIN locations l ON l.id=r.location_id LEFT JOIN vehicle_cases c ON c.id=r.vehicle_case_id WHERE r.vehicle_case_id=? ORDER BY r.submitted_at DESC`).all(caseId).map(summarizeReport);
  const history = db.prepare(`SELECT h.*,u.name FROM review_history h LEFT JOIN staff_users u ON u.id=h.staff_user_id WHERE h.vehicle_case_id=? ORDER BY h.created_at DESC`).all(caseId);
  sendJson(res, 200, { item, reports, history });
}
async function updateCase(req, res, caseId) {
  const session = requireStaff(req, res, ['Case Manager', 'Administrator'], true); if (!session) return;
  let body; try { body = await readJson(req, 128 * 1024); } catch (error) { return sendText(res, 400, error.message); }
  const item = db.prepare('SELECT * FROM vehicle_cases WHERE id=?').get(caseId); if (!item) return sendText(res, 404, 'Vehicle case not found.');
  const next = clean(body.status, 40); if (!validCaseStatus.has(next)) return sendText(res, 400, 'Choose a valid vehicle case status.');
  const note = clean(body.note, 1400); const resolvedAt = next === 'Resolved' ? now() : null;
  db.prepare('UPDATE vehicle_cases SET status=?,resolution_note=CASE WHEN ? IS NULL THEN resolution_note ELSE ? END,updated_at=?,resolved_at=? WHERE id=?')
    .run(next, note || null, note || null, now(), resolvedAt, caseId);
  addHistory({ caseId, userId: session.user_id, action: 'Vehicle case status changed', previous: item.status, next, notes: note || null });
  audit('staff', session.user_id, 'Vehicle case status changed', 'vehicle_case', item.case_id, { previous: item.status, next, note });
  sendJson(res, 200, { ok: true, status: next });
}
async function duplicateAction(req, res, reportId) {
  const session = requireStaff(req, res, ['Reviewer', 'Case Manager', 'Administrator'], true); if (!session) return;
  let body; try { body = await readJson(req, 128 * 1024); } catch (error) { return sendText(res, 400, error.message); }
  const report = reportRowById(reportId); if (!report) return sendText(res, 404, 'Report not found.');
  const action = clean(body.action, 40); const target = clean(body.targetCaseId, 32); const note = clean(body.note, 600);
  if (action === 'link') {
    if (!['Case Manager', 'Administrator'].includes(session.role)) return sendText(res, 403, 'Only case managers can link reports.');
    const caseRow = db.prepare('SELECT * FROM vehicle_cases WHERE case_id=?').get(target); if (!caseRow) return sendText(res, 404, 'Vehicle case not found.');
    db.prepare("UPDATE reports SET vehicle_case_id=?,status='Duplicate',updated_at=? WHERE id=?").run(caseRow.id, now(), reportId);
    addHistory({ reportId, caseId: caseRow.id, userId: session.user_id, action: 'Duplicate confirmed and linked', previous: report.status, next: 'Duplicate', notes: note || null });
    audit('staff', session.user_id, 'Duplicate confirmed', 'report', report.report_id, { caseId: caseRow.case_id });
  } else if (action === 'not-match' || action === 'later') {
    addHistory({ reportId, userId: session.user_id, action: action === 'not-match' ? 'Possible duplicate marked not a match' : 'Possible duplicate deferred', notes: note || null });
    audit('staff', session.user_id, action === 'not-match' ? 'Duplicate marked not a match' : 'Duplicate review deferred', 'report', report.report_id);
  } else return sendText(res, 400, 'Choose a duplicate-review action.');
  sendJson(res, 200, { ok: true });
}
function mapData(req, res, url) {
  if (!requireStaff(req, res)) return;
  const requested = clean(url.searchParams.get('status'), 40); const values = [];
  let where = "WHERE c.status NOT IN ('Resolved','Archived')";
  if (requested && validCaseStatus.has(requested)) { where = 'WHERE c.status=?'; values.push(requested); }
  const rows = db.prepare(`SELECT c.id,c.case_id,c.status,c.vehicle_make,c.vehicle_model,c.vehicle_color,c.plate,l.address,l.latitude,l.longitude FROM vehicle_cases c LEFT JOIN locations l ON l.id=c.location_id ${where} ORDER BY c.updated_at DESC`).all(...values);
  sendJson(res, 200, { rows });
}
function stats(req, res) {
  if (!requireStaff(req, res)) return;
  const byReport = db.prepare('SELECT status,count(*) AS count FROM reports GROUP BY status ORDER BY count DESC').all();
  const byCase = db.prepare('SELECT status,count(*) AS count FROM vehicle_cases GROUP BY status ORDER BY count DESC').all();
  const monthly = db.prepare("SELECT substr(submitted_at,1,7) AS month,count(*) AS count FROM reports GROUP BY substr(submitted_at,1,7) ORDER BY month DESC LIMIT 12").all().reverse();
  sendJson(res, 200, { byReport, byCase, monthly });
}

const server = http.createServer(async (req, res) => {
  setSecurityHeaders(res);
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = decodeURIComponent(url.pathname);
  try {
    if (pathname === '/api/public/reports' && req.method === 'POST') return publicSubmit(req, res);
    if (pathname === '/api/public/status' && req.method === 'GET') {
      const id = clean(url.searchParams.get('id'), 32).toUpperCase(); const row = reportRowByPublicId(id);
      if (!row) return sendText(res, 404, 'No report was found with that Report ID.');
      return sendJson(res, 200, { reportId: row.report_id, status: row.status, submittedAt: row.submitted_at, observedAt: row.observed_at || null, publicMessage: 'County staff review each report before deciding next steps.' });
    }
    if (pathname === '/api/auth/login' && req.method === 'POST') return staffLogin(req, res);
    if (pathname === '/api/auth/logout' && req.method === 'POST') {
      const session = requireStaff(req, res, null, true); if (!session) return;
      db.prepare('DELETE FROM sessions WHERE token_hash=?').run(session.token_hash); clearSession(res); audit('staff', session.user_id, 'Signed out', 'staff_user', session.user_id); return sendJson(res, 200, { ok: true });
    }
    if (pathname === '/api/auth/me' && req.method === 'GET') { const session = requireStaff(req, res); if (session) sendJson(res, 200, { user: staffUser(session), csrfToken: session.csrf_token }); return; }
    if (pathname === '/api/staff/dashboard' && req.method === 'GET') return dashboard(req, res);
    if (pathname === '/api/staff/reports' && req.method === 'GET') return listReports(req, res, url);
    if (pathname === '/api/staff/cases' && req.method === 'GET') return listCases(req, res, url);
    if (pathname === '/api/staff/map' && req.method === 'GET') return mapData(req, res, url);
    if (pathname === '/api/staff/stats' && req.method === 'GET') return stats(req, res);
    const photoMatch = pathname.match(/^\/api\/staff\/photos\/(\d+)$/);
    if (photoMatch && req.method === 'GET') return servePrivatePhoto(req, res, Number(photoMatch[1]));
    const reportMatch = pathname.match(/^\/api\/staff\/reports\/(\d+)(?:\/(note|case|duplicate))?$/);
    if (reportMatch) {
      const id = Number(reportMatch[1]); const action = reportMatch[2];
      if (!action && req.method === 'GET') return reportDetail(req, res, id);
      if (!action && req.method === 'PATCH') return updateReport(req, res, id);
      if (action === 'note' && req.method === 'POST') return addNote(req, res, id);
      if (action === 'case' && req.method === 'POST') return createOrLinkCase(req, res, id);
      if (action === 'duplicate' && req.method === 'POST') return duplicateAction(req, res, id);
    }
    const caseMatch = pathname.match(/^\/api\/staff\/cases\/(\d+)$/);
    if (caseMatch) { if (req.method === 'GET') return caseDetail(req, res, Number(caseMatch[1])); if (req.method === 'PATCH') return updateCase(req, res, Number(caseMatch[1])); }
    if (pathname.startsWith('/api/')) return sendText(res, 404, 'API endpoint not found.');
    if (pathname.startsWith('/uploads/')) return sendText(res, 403, 'Private uploads are not available from this address.');
    const requested = pathname === '/' ? 'index.html' : pathname.replace(/^\//, '');
    const direct = path.resolve(PUBLIC_DIR, requested);
    if (direct.startsWith(PUBLIC_DIR) && fs.existsSync(direct) && fs.statSync(direct).isFile()) return serveFile(res, direct);
    return serveFile(res, path.join(PUBLIC_DIR, 'index.html'));
  } catch (error) {
    console.error(error);
    if (!res.headersSent) sendText(res, 500, 'Something went wrong. Please try again.'); else res.end();
  }
});
server.listen(PORT, () => console.log(`VehicleWatch running at http://localhost:${PORT}`));
