import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import cookieParser from 'cookie-parser';
import pkg from 'pg';
import dns from 'dns/promises'; // 👈 añadido para resolver IPv4

const { Pool } = pkg;
const app = express();
app.use(express.json());
app.use(cookieParser());

const ORIGIN = process.env.CORS_ORIGIN || 'http://localhost:5173';
app.use(cors({ origin: ORIGIN, credentials: true }));

// ---------- Conexión a PostgreSQL con IPv4 y SSL ----------
const conn = new URL(process.env.DATABASE_URL);
const { address: ipv4 } = await dns.lookup(conn.hostname, { family: 4 }); // fuerza IPv4
const pool = new Pool({
  host: ipv4,
  port: Number(conn.port || 5432),
  database: conn.pathname.slice(1),
  user: decodeURIComponent(conn.username),
  password: decodeURIComponent(conn.password),
  ssl: { rejectUnauthorized: false } // sslmode=require
});

// ---------- Configuración de JWT y Cookies ----------
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret';
const COOKIE_DOMAIN = process.env.COOKIE_DOMAIN || undefined;
const COOKIE_SECURE = String(process.env.COOKIE_SECURE || 'false') === 'true';

function setCookie(res, name, token) {
  res.cookie(name, token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: COOKIE_SECURE,
    domain: COOKIE_DOMAIN,
    path: '/'
  });
}
function clearCookie(res, name) {
  res.clearCookie(name, { domain: COOKIE_DOMAIN, path: '/' });
}
function getClientIP(req) {
  const xff = (req.headers['x-forwarded-for'] || '').toString().split(',')[0].trim();
  return xff || req.socket.remoteAddress || '';
}
function toRad(x) { return x * Math.PI / 180; }
function haversine(lat1, lon1, lat2, lon2) {
  const R = 6371000;
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a = Math.sin(dLat / 2) ** 2 +
            Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) ** 2;
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

// ---------- Middlewares ----------
function adminAuth(req, res, next) {
  const token = req.cookies['admin_jwt'];
  if (!token) return res.status(401).json({ error: 'No session' });
  try {
    const data = jwt.verify(token, JWT_SECRET);
    if (data.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
    req.admin = data;
    next();
  } catch { return res.status(401).json({ error: 'Invalid token' }); }
}
function employeeAuth(req, res, next) {
  const token = req.cookies['emp_jwt'];
  if (!token) return res.status(401).json({ error: 'No session' });
  try {
    const data = jwt.verify(token, JWT_SECRET);
    if (data.role !== 'employee') return res.status(403).json({ error: 'Forbidden' });
    req.employee = data;
    next();
  } catch { return res.status(401).json({ error: 'Invalid token' }); }
}

// ---------- Rutas de Admin ----------
app.post('/api/admin/signup', async (req, res) => {
  const { email, password, company_name } = req.body;
  if (!email || !password || !company_name) return res.status(400).json({ error: 'Missing fields' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const slug = company_name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '');
    const { rows: tRows } = await client.query(`insert into tenants (slug,name) values ($1,$2) returning id, slug`, [slug, company_name]);
    const tenant = tRows[0];
    const hash = await bcrypt.hash(password, 10);
    await client.query(`insert into admins (tenant_id,email,password_hash,role) values ($1,$2,$3,'owner')`, [tenant.id, email, hash]);
    await client.query(`insert into tenant_settings (tenant_id,enforce_device,enforce_ip,enforce_geofence,timezone) values ($1,true,false,true,'America/Merida')`, [tenant.id]);
    await client.query('COMMIT');
    const token = jwt.sign({ role: 'admin', email, tenant_id: tenant.id, slug: tenant.slug }, JWT_SECRET, { expiresIn: '12h' });
    setCookie(res, 'admin_jwt', token);
    res.json({ ok: true, slug: tenant.slug });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error(e);
    res.status(500).json({ error: 'Signup failed' });
  } finally { client.release(); }
});

app.post('/api/admin/login', async (req, res) => {
  const { email, password } = req.body;
  const { rows } = await pool.query(`select a.password_hash, a.tenant_id, t.slug from admins a join tenants t on t.id=a.tenant_id where a.email=$1`, [email]);
  const row = rows[0];
  if (!row) return res.status(401).json({ error: 'Invalid credentials' });
  const ok = await bcrypt.compare(password, row.password_hash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ role: 'admin', email, tenant_id: row.tenant_id, slug: row.slug }, JWT_SECRET, { expiresIn: '12h' });
  setCookie(res, 'admin_jwt', token);
  res.json({ ok: true, slug: row.slug });
});

app.post('/api/admin/logout', (req, res) => { clearCookie(res, 'admin_jwt'); res.json({ ok: true }); });
app.get('/api/admin/me', adminAuth, (req, res) => { res.json({ email: req.admin.email, slug: req.admin.slug }); });

// ---------- Aquí irían TODAS las demás rutas igual que ya las tienes ----------
// (settings, schedules, locations, employees, events, employee login, punches, reports…)
// No cambiamos su lógica, solo la conexión a la base arriba.

app.get('/api/health', (req, res) => res.json({ ok: true }));

// ---------- Inicio del servidor ----------
const port = process.env.PORT || 8080;
app.listen(port, () => console.log('Checador backend cloud listening on', port));
