import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import cookieParser from 'cookie-parser';
import pkg from 'pg';
import dns from 'dns/promises';

const { Pool } = pkg;

const app = express();
app.set('trust proxy', 1); // cookies secure detrás de proxy (Render)
app.use(express.json());
app.use(cookieParser());

/** ===== CORS =====
 * Pon en Render -> Environment:
 * CORS_ORIGIN = https://TU-DOMINIO-NETLIFY.netlify.app
 * (ej. https://steady-cheesecake-935a51.netlify.app)
 */
const ORIGIN = process.env.CORS_ORIGIN || '';
app.use(cors({
  origin: (origin, cb) => {
    // Permite llamadas desde tu Netlify (o desde herramientas sin origin, p.ej. curl)
    if (!origin || origin === ORIGIN) return cb(null, true);
    return cb(new Error('Not allowed by CORS'));
  },
  credentials: true
}));

// --- Utils / Cookies ---
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret';

/** Cookies cross-site correctas (Netlify<->Render) */
function setCookie(res, name, token) {
  res.cookie(name, token, {
    httpOnly: true,
    sameSite: 'none',  // << antes 'lax'
    secure: true,      // << obligatorio con SameSite=None
    path: '/'
  });
}
function clearCookie(res, name) { res.clearCookie(name, { path: '/' }); }

function getClientIP(req) {
  const xff = (req.headers['x-forwarded-for'] || '').toString().split(',')[0].trim();
  return xff || req.socket.remoteAddress || '';
}
function toRad(x){ return x * Math.PI / 180; }
function haversine(lat1, lon1, lat2, lon2) {
  const R = 6371000;
  const dLat = toRad(lat2 - lat1), dLon = toRad(lon2 - lon1);
  const a = Math.sin(dLat/2)**2 + Math.cos(toRad(lat1))*Math.cos(toRad(lat2))*Math.sin(dLon/2)**2;
  return 2 * R * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
}

let pool = null; // se inicializa en start()

// ---- Diagnóstico ----
app.get('/api/health', (req,res)=> res.json({ ok:true }));
app.get('/api/dbhost', (req,res)=>{
  try {
    const u = new URL(process.env.DATABASE_URL);
    res.json({ host: u.hostname, port: u.port, sslmode: u.searchParams.get('sslmode') });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/dbcheck', async (req,res)=>{
  try {
    if (!pool) return res.status(503).json({ error:'pool not ready' });
    const { rows } = await pool.query('select 1 as ok');
    res.json({ db: 'ok', rows });
  } catch (e) {
    console.error('DBCHECK ERROR:', e);
    res.status(500).json({ db: 'error', message: e.message, code: e.code });
  }
});

// -------- Middlewares (cookie JWT) --------
function adminAuth(req, res, next) {
  const token = req.cookies['admin_jwt'];
  if (!token) return res.status(401).json({ error: 'No session' });
  try {
    const data = jwt.verify(token, JWT_SECRET);
    if (data.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
    req.admin = data; next();
  } catch { return res.status(401).json({ error: 'Invalid token' }); }
}
function employeeAuth(req, res, next) {
  const token = req.cookies['emp_jwt'];
  if (!token) return res.status(401).json({ error: 'No session' });
  try {
    const data = jwt.verify(token, JWT_SECRET);
    if (data.role !== 'employee') return res.status(403).json({ error: 'Forbidden' });
    req.employee = data; next();
  } catch { return res.status(401).json({ error: 'Invalid token' }); }
}

// -------- Admin auth --------
app.post('/api/admin/signup', async (req, res) => {
  const { email, password, company_name } = req.body;
  if (!email || !password || !company_name) return res.status(400).json({ error: 'Missing fields' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const slug = company_name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g,'');
    const { rows: tRows } = await client.query(`insert into tenants (slug,name) values ($1,$2) returning id, slug`, [slug, company_name]);
    const tenant = tRows[0];
    const hash = await bcrypt.hash(password, 10);
    await client.query(`insert into admins (tenant_id,email,password_hash,role) values ($1,$2,$3,'owner')`, [tenant.id, email, hash]);
    await client.query(`insert into tenant_settings (tenant_id,enforce_device,enforce_ip,enforce_geofence,timezone) values ($1,true,false,true,'America/Merida')`, [tenant.id]);
    await client.query('COMMIT');
    const token = jwt.sign({ role:'admin', email, tenant_id: tenant.id, slug: tenant.slug }, JWT_SECRET, { expiresIn: '12h' });
    setCookie(res, 'admin_jwt', token);
    res.json({ ok:true, slug: tenant.slug });
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
  const token = jwt.sign({ role:'admin', email, tenant_id: row.tenant_id, slug: row.slug }, JWT_SECRET, { expiresIn: '12h' });
  setCookie(res, 'admin_jwt', token);
  res.json({ ok:true, slug: row.slug });
});
app.post('/api/admin/logout', (req, res) => { clearCookie(res,'admin_jwt'); res.json({ok:true}); });
app.get('/api/admin/me', adminAuth, (req, res) => { res.json({ email: req.admin.email, slug: req.admin.slug }); });

// -------- Admin config --------
app.get('/api/admin/settings', adminAuth, async (req,res)=>{
  const tenant_id = req.admin.tenant_id;
  const [locs, emps] = await Promise.all([
    pool.query(`select id,label,lat,lng,radius_m from locations where tenant_id=$1 order by created_at desc`, [tenant_id]),
    pool.query(`select id,full_name,pin from employees where tenant_id=$1 and is_active=true order by created_at desc`, [tenant_id])
  ]);
  res.json({ locations: locs.rows, employees: emps.rows });
});
app.post('/api/admin/settings', adminAuth, async (req,res)=>{
  const tenant_id = req.admin.tenant_id;
  const { enforce_device, enforce_ip, enforce_geofence, timezone } = req.body;
  await pool.query(
    `insert into tenant_settings (tenant_id,enforce_device,enforce_ip,enforce_geofence,timezone)
     values ($1,$2,$3,$4,coalesce($5,'America/Merida'))
     on conflict (tenant_id) do update set enforce_device=excluded.enforce_device, enforce_ip=excluded.enforce_ip, enforce_geofence=excluded.enforce_geofence, timezone=excluded.timezone`,
    [tenant_id, !!enforce_device, !!enforce_ip, !!enforce_geofence, timezone||'America/Merida']
  );
  res.json({ ok:true });
});
app.post('/api/admin/schedules', adminAuth, async (req,res)=>{
  const tenant_id = req.admin.tenant_id;
  const { check_in_start, check_in_end, check_out_start, check_out_end, lunch_minutes, overtime_after_minutes } = req.body;
  await pool.query(
    `insert into schedules (tenant_id,name,check_in_start,check_in_end,check_out_start,check_out_end,lunch_minutes,overtime_after_minutes)
     values ($1,'Horario base',$2,$3,$4,$5,$6,$7)`,
    [tenant_id, check_in_start, check_in_end, check_out_start, check_out_end, lunch_minutes||60, overtime_after_minutes||480]
  );
  res.json({ ok:true });
});
app.post('/api/admin/locations', adminAuth, async (req,res)=>{
  const tenant_id = req.admin.tenant_id;
  const { label, lat, lng, radius_m } = req.body;
  await pool.query(`insert into locations (tenant_id,label,lat,lng,radius_m) values ($1,$2,$3,$4,$5)`,
    [tenant_id, label, Number(lat), Number(lng), Number(radius_m||150)]);
  res.json({ ok:true });
});
app.post('/api/admin/employees', adminAuth, async (req,res)=>{
  const tenant_id = req.admin.tenant_id;
  const { full_name, pin } = req.body;
  if (!full_name || !pin) return res.status(400).json({ error: 'Missing fields' });
  await pool.query(`insert into employees (tenant_id,full_name,pin) values ($1,$2,$3)`, [tenant_id, full_name, pin]);
  res.json({ ok:true });
});

// -------- SSE events --------
const sseClients = new Map(); // tenant_id -> Set(res)
function sseBroadcast(tenant_id, data) {
  const set = sseClients.get(tenant_id);
  if (!set) return;
  const payload = `data: ${JSON.stringify(data)}\n\n`;
  for (const res of set) { try { res.write(payload); } catch {} }
}
app.get('/api/admin/events/:slug', adminAuth, async (req,res)=>{
  const slug = req.params.slug;
  if (slug !== req.admin.slug) return res.status(403).end();
  res.writeHead(200, {
    'Content-Type':'text/event-stream',
    'Cache-Control':'no-cache',
    'Connection':'keep-alive',
    'Access-Control-Allow-Origin': ORIGIN,          // << CORS para SSE
    'Access-Control-Allow-Credentials': 'true'
  });
  res.write('\n');
  let set = sseClients.get(req.admin.tenant_id);
  if (!set) { set = new Set(); sseClients.set(req.admin.tenant_id, set); }
  set.add(res);
  req.on('close', ()=> set.delete(res));
});

// -------- Employee auth --------
app.post('/api/employee/login', async (req,res)=>{
  const { slug, pin } = req.body;
  const { rows: tRows } = await pool.query(`select id from tenants where slug=$1`, [slug]);
  const tenant = tRows[0];
  if (!tenant) return res.status(404).json({ error: 'Empresa no encontrada' });
  const { rows: eRows } = await pool.query(`select id,full_name from employees where tenant_id=$1 and pin=$2 and is_active=true`, [tenant.id, pin]);
  const emp = eRows[0];
  if (!emp) return res.status(401).json({ error: 'PIN inválido' });
  const token = jwt.sign({ role:'employee', employee_id: emp.id, tenant_id: tenant.id }, JWT_SECRET, { expiresIn: '12h' });
  setCookie(res, 'emp_jwt', token);
  res.json({ ok:true, full_name: emp.full_name });
});
app.post('/api/employee/logout', (req,res)=>{ clearCookie(res,'emp_jwt'); res.json({ok:true}); });
app.get('/api/employee/me', async (req,res)=>{
  try {
    const data = jwt.verify(req.cookies['emp_jwt']||'', JWT_SECRET);
    const { rows } = await pool.query(`select full_name from employees where id=$1`, [data.employee_id]);
    const { rows: dev } = await pool.query(`select 1 from devices where employee_id=$1 limit 1`, [data.employee_id]);
    res.json({ full_name: rows[0]?.full_name || null, device_registered: !!dev[0] });
  } catch { res.json({}); }
});

// -------- Employee actions --------
app.post('/api/employee/register_device', async (req,res)=>{
  try {
    const data = jwt.verify(req.cookies['emp_jwt']||'', JWT_SECRET);
    const { fingerprint, lat, lng } = req.body;
    const ip = getClientIP(req);
    await pool.query(
      `insert into devices (tenant_id,employee_id,device_fingerprint,registered_ip_inet,is_locked)
       values ($1,$2,$3,$4,true)
       on conflict (tenant_id,employee_id,device_fingerprint)
       do update set registered_ip_inet=excluded.registered_ip_inet, is_locked=true`,
      [data.tenant_id, data.employee_id, fingerprint, ip]
    );
    res.json({ ok:true });
  } catch { res.status(401).json({ error:'No session' }); }
});

app.post('/api/employee/punch', async (req,res)=>{
  try {
    const data = jwt.verify(req.cookies['emp_jwt']||'', JWT_SECRET);
    const { type, lat, lng, fingerprint } = req.body;
    if (!['IN','OUT','LUNCH_IN','LUNCH_OUT'].includes(type)) return res.status(400).json({ error:'Tipo inválido' });
    const ip = getClientIP(req);

    const { rows: polRows } = await pool.query(`select enforce_device,enforce_ip,enforce_geofence from tenant_settings where tenant_id=$1`, [data.tenant_id]);
    const pol = polRows[0] || { enforce_device: true, enforce_ip: false, enforce_geofence: true };

    let device_ok = true;
    if (pol.enforce_device) {
      const { rows } = await pool.query(`select 1 from devices where tenant_id=$1 and employee_id=$2 and device_fingerprint=$3`, [data.tenant_id, data.employee_id, fingerprint||'']);
      device_ok = !!rows[0];
    }
    let ip_ok = true;
    if (pol.enforce_ip) {
      const { rows } = await pool.query(`select 1 from devices where tenant_id=$1 and employee_id=$2 and registered_ip_inet=$3::inet`, [data.tenant_id, data.employee_id, ip]);
      ip_ok = !!rows[0];
    }
    let location_ok = true;
    if (pol.enforce_geofence) {
      const { rows: locs } = await pool.query(`select lat,lng,radius_m from locations where tenant_id=$1`, [data.tenant_id]);
      location_ok = false;
      for (const l of locs) {
        const dist = haversine(Number(lat), Number(lng), Number(l.lat), Number(l.lng));
        if (dist <= Number(l.radius_m)) { location_ok = true; break; }
      }
    }

    const { rows: empName } = await pool.query(`select full_name from employees where id=$1`, [data.employee_id]);
    const name = empName[0]?.full_name || '';

    const ins = await pool.query(
      `insert into punches (tenant_id,employee_id,punch_type,client_ip,lat,lng,location_ok,ip_ok,device_ok)
       values ($1,$2,$3,$4,$5,$6,$7,$8,$9) returning punched_at`,
      [data.tenant_id, data.employee_id, type, ip, lat, lng, location_ok, ip_ok, device_ok]
    );
    // Opcional: sseBroadcast(...)
    res.json({ ok:true, punched_at: ins.rows[0].punched_at });
  } catch { res.status(401).json({ error:'No session' }); }
});

// ---- Inicio del servidor: intenta DB pero NO te caes si falla
async function start() {
  try {
    if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL not set');
    const u = new URL(process.env.DATABASE_URL);
    // Fuerza IPv4 (pooler de Supabase es IPv4)
    const { address: ipv4 } = await dns.lookup(u.hostname, { family: 4 });
    pool = new Pool({
      host: ipv4,
      port: Number(u.port || 5432),
      database: u.pathname.slice(1),
      user: decodeURIComponent(u.username),
      password: decodeURIComponent(u.password),
      ssl: { rejectUnauthorized: false }
    });
    await pool.query('select 1'); // test inicial
    console.log('DB ready');
  } catch (e) {
    console.error('DB START WARN:', e.message);
    // No hacemos process.exit(1) -> dejamos que el server arranque
  }
  const port = process.env.PORT || 8080;
  app.listen(port, ()=> console.log('Checador backend cloud listening on', port));
}
start();
