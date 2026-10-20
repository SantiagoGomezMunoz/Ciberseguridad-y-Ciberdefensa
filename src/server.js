require('dotenv').config();
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const session = require('express-session');
const PgStore = require('connect-pg-simple')(session);
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const pool = require('./db');
const fs = require('fs');
const http = require('http');
const https = require('https');
const { logSeguridad } = require('./logger');

const DEMO = process.env.DEMO_MODE === 'true';
if (!DEMO && (!process.env.SESSION_SECRET || !process.env.DATABASE_URL)) {
  console.error('Faltan variables en .env (SESSION_SECRET, DATABASE_URL). Copia .env.example a .env o usa: npm run demo');
  process.exit(1);
}

// A07/A02: el secreto de sesión debe ser largo y no estar en valores por defecto
if (!DEMO && (process.env.SESSION_SECRET.length < 32 || /cambia_este_secreto/.test(process.env.SESSION_SECRET))) {
  console.error('SESSION_SECRET débil: usa mínimo 32 caracteres. Genera uno con: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"');
  process.exit(1);
}
// HTTPS opcional directamente desde la app (A02). Si hay certificado, la cookie de sesión pasa a Secure.
const USE_HTTPS = !!(process.env.SSL_KEY && process.env.SSL_CERT);
const COOKIE_SECURE = USE_HTTPS || process.env.COOKIE_SECURE === 'true';

class UserError extends Error {}
const app = express();
if (process.env.TRUST_PROXY === 'true') app.set('trust proxy', 1);
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '..', 'views'));

app.disable('x-powered-by');
// A05: CSP estricta, sin comodines ni 'unsafe-inline' (las vistas ya no usan estilos ni scripts en línea)
app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: false,
    directives: {
      'default-src': ["'self'"],
      'script-src': ["'self'"],
      'script-src-attr': ["'none'"],
      'style-src': ["'self'"],
      'img-src': ["'self'"],
      'font-src': ["'self'"],
      'connect-src': ["'self'"],
      // Directivas definidas de forma explícita (ZAP marca como débil cualquier directiva ausente o con comodín)
      'frame-src': ["'none'"],
      'child-src': ["'none'"],
      'worker-src': ["'none'"],
      'manifest-src': ["'self'"],
      'media-src': ["'none'"],
      'prefetch-src': ["'none'"],
      'form-action': ["'self'"],
      'frame-ancestors': ["'none'"],
      'base-uri': ["'self'"],
      'object-src': ["'none'"],
      ...(USE_HTTPS ? { 'upgrade-insecure-requests': [] } : {})
    }
  },
  // HSTS solo cuando realmente se sirve por HTTPS (en HTTP el navegador lo ignora)
  hsts: USE_HTTPS || process.env.COOKIE_SECURE === 'true' ? { maxAge: 15552000, includeSubDomains: true } : false,
  frameguard: { action: 'deny' }
}));
// Las páginas autenticadas no deben quedar en caché del navegador ni de proxies
app.use((req, res, next) => { if (req.path !== '/style.css') res.set('Cache-Control', 'no-store'); next(); });
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, '..', 'public')));
app.use(session({
  store: DEMO ? undefined : new PgStore({ pool }), // en modo demo las sesiones quedan en memoria
  name: 'bd.sid', // nombre propio: no revela que es Express (connect.sid)
  secret: process.env.SESSION_SECRET || 'secreto-solo-para-demo',
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: { httpOnly: true, sameSite: 'lax', secure: COOKIE_SECURE, maxAge: 15 * 60 * 1000 }
}));

// Variables de vista + protección CSRF
app.use((req, res, next) => {
  if (!req.session.csrf) req.session.csrf = crypto.randomBytes(24).toString('hex');
  res.locals.csrf = req.session.csrf;
  res.locals.user = req.session.user || null;
  res.locals.error = null;
  res.locals.ok = null;
  res.locals.path = req.path;
  res.locals.cop = n => Number(n).toLocaleString('es-CO', { style: 'currency', currency: 'COP', minimumFractionDigits: 2, maximumFractionDigits: 2 });
  res.locals.fecha = d => new Date(d).toLocaleString('es-CO');
  if (req.method === 'POST' && req.body._csrf !== req.session.csrf) {
    logSeguridad('csrf_invalido', req);
    return res.status(403).send('Token CSRF inválido');
  }
  next();
});

const requireAuth = (req, res, next) => {
  if (req.session.user) return next();
  logSeguridad('acceso_no_autenticado', req);
  res.redirect('/login');
};
const limitHandler = (req, res) => { logSeguridad('rate_limit', req); res.status(429).send('Demasiadas solicitudes. Intenta más tarde.'); };
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false, handler: limitHandler });
const transferLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 60, standardHeaders: true, legacyHeaders: false, handler: limitHandler });
const DUMMY_HASH = bcrypt.hashSync('relleno-anti-timing', 12);
const wrap = fn => (req, res, next) => fn(req, res, next).catch(next);

app.get('/', (req, res) => res.redirect(req.session.user ? '/dashboard' : '/login'));

// ---------- Registro ----------
app.get('/register', (req, res) => res.render('register', { form: {} }));
app.post('/register', loginLimiter, wrap(async (req, res) => {
  const { nombre = '', documento = '', email = '', password = '', password2 = '' } = req.body;
  const form = { nombre, documento, email };
  const fail = msg => res.status(400).render('register', { form, error: msg });
  if (nombre.trim().length < 3 || nombre.length > 100) return fail('Escribe tu nombre completo.');
  if (!/^\d{6,12}$/.test(documento)) return fail('El documento debe tener entre 6 y 12 dígitos.');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 120) return fail('Correo electrónico no válido.');
  if (password.length < 10 || !/[a-zA-Z]/.test(password) || !/\d/.test(password)) return fail('La contraseña debe tener mínimo 10 caracteres, con letras y números.');
  if (password !== password2) return fail('Las contraseñas no coinciden.');

  const hash = await bcrypt.hash(password, 12);
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    const u = await c.query('INSERT INTO usuarios (nombre, documento, email, password_hash) VALUES ($1,$2,$3,$4) RETURNING id',
      [nombre.trim(), documento, email.toLowerCase(), hash]);
    const numero = String(crypto.randomInt(1e9, 1e10));
    // Saldo de bienvenida solo para la demostración
    await c.query('INSERT INTO cuentas (usuario_id, numero, saldo) VALUES ($1,$2,1000000)', [u.rows[0].id, numero]);
    await c.query('COMMIT');
  } catch (e) {
    await c.query('ROLLBACK');
    if (e.code === '23505') return fail('Ya existe una cuenta con ese documento o correo.');
    throw e;
  } finally { c.release(); }
  logSeguridad('registro_exitoso', req, { email });
  res.render('login', { ok: 'Registro exitoso. Ya puedes iniciar sesión.' });
}));

// ---------- Login / Logout ----------
app.get('/login', (req, res) => res.render('login'));
app.post('/login', loginLimiter, wrap(async (req, res) => {
  const { email = '', password = '' } = req.body;
  const fail = (msg, evento = 'login_fallido') => { logSeguridad(evento, req, { email }); return res.status(401).render('login', { error: msg }); };
  const u = (await pool.query('SELECT * FROM usuarios WHERE email = $1', [email.toLowerCase()])).rows[0];
  if (u && u.bloqueado_hasta && u.bloqueado_hasta > new Date()) return fail('Correo o contraseña incorrectos, o cuenta bloqueada temporalmente.', 'login_cuenta_bloqueada'); // mensaje genérico: no revela si la cuenta existe
  const valido = await bcrypt.compare(password, u ? u.password_hash : DUMMY_HASH);
  if (!u || !valido) {
    if (u) await pool.query(
      `UPDATE usuarios SET
         bloqueado_hasta = CASE WHEN intentos_fallidos + 1 >= 5 THEN now() + interval '15 minutes' END,
         intentos_fallidos = CASE WHEN intentos_fallidos + 1 >= 5 THEN 0 ELSE intentos_fallidos + 1 END
       WHERE id = $1`, [u.id]);
    return fail('Correo o contraseña incorrectos.');
  }
  await pool.query('UPDATE usuarios SET intentos_fallidos = 0, bloqueado_hasta = NULL WHERE id = $1', [u.id]);
  req.session.regenerate(err => {
    if (err) return res.status(500).send('Error interno del servidor');
    req.session.user = { id: u.id, nombre: u.nombre };
    logSeguridad('login_exitoso', req);
    res.redirect('/dashboard');
  });
}));
app.post('/logout', (req, res) => {
  logSeguridad('logout', req);
  req.session.destroy(() => { res.clearCookie('bd.sid'); res.redirect('/login'); });
});

// ---------- Panel ----------
const miCuenta = async uid => (await pool.query('SELECT * FROM cuentas WHERE usuario_id = $1', [uid])).rows[0];
const movimientos = (cuentaId, limite, offset = 0) => pool.query(
  `SELECT t.*, (t.cuenta_origen = $1) AS saliente, co.numero AS num_origen, cd.numero AS num_destino
   FROM transacciones t
   LEFT JOIN cuentas co ON co.id = t.cuenta_origen
   LEFT JOIN cuentas cd ON cd.id = t.cuenta_destino
   WHERE t.cuenta_origen = $1 OR t.cuenta_destino = $1
   ORDER BY t.creado_en DESC, t.id DESC LIMIT $2 OFFSET $3`, [cuentaId, limite, offset]);

app.get('/dashboard', requireAuth, wrap(async (req, res) => {
  const cuenta = await miCuenta(req.session.user.id);
  res.render('dashboard', { cuenta, ultimos: (await movimientos(cuenta.id, 5)).rows });
}));

app.get('/movimientos', requireAuth, wrap(async (req, res) => {
  const cuenta = await miCuenta(req.session.user.id);
  const pagina = Math.max(1, parseInt(req.query.p, 10) || 1);
  const r = await movimientos(cuenta.id, 21, (pagina - 1) * 20);
  res.render('movimientos', { cuenta, items: r.rows.slice(0, 20), hayMas: r.rows.length > 20, pagina });
}));

// ---------- Transferencias ----------
app.get('/transferir', requireAuth, wrap(async (req, res) => res.render('transferir', { cuenta: await miCuenta(req.session.user.id), form: {} })));
app.post('/transferir', requireAuth, transferLimiter, wrap(async (req, res) => {
  const { destino = '', monto = '', descripcion = '' } = req.body;
  const c = await pool.connect();
  try {
    if (!/^\d{10}$/.test(destino)) throw new UserError('El número de cuenta destino debe tener 10 dígitos.');
    if (!/^\d{1,10}(\.\d{1,2})?$/.test(monto) || Number(monto) <= 0) throw new UserError('Ingresa un monto válido mayor a cero.');
    await c.query('BEGIN');
    const o = (await c.query('SELECT id FROM cuentas WHERE usuario_id = $1', [req.session.user.id])).rows[0];
    const d = (await c.query('SELECT id FROM cuentas WHERE numero = $1', [destino])).rows[0];
    if (!d) throw new UserError('La cuenta destino no existe.');
    if (d.id === o.id) throw new UserError('No puedes transferir a tu propia cuenta.');
    await c.query('SELECT id FROM cuentas WHERE id IN ($1,$2) ORDER BY id FOR UPDATE', [o.id, d.id]); // bloqueo en orden fijo
    const debito = await c.query('UPDATE cuentas SET saldo = saldo - $1 WHERE id = $2 AND saldo >= $1', [monto, o.id]);
    if (!debito.rowCount) throw new UserError('Saldo insuficiente.');
    await c.query('UPDATE cuentas SET saldo = saldo + $1 WHERE id = $2', [monto, d.id]);
    await c.query('INSERT INTO transacciones (cuenta_origen, cuenta_destino, monto, descripcion) VALUES ($1,$2,$3,$4)',
      [o.id, d.id, monto, descripcion.trim().slice(0, 140)]);
    await c.query('COMMIT');
    logSeguridad('transferencia_exitosa', req, { destino, monto });
  } catch (e) {
    await c.query('ROLLBACK').catch(() => {});
    if (!(e instanceof UserError)) throw e;
    logSeguridad('transferencia_rechazada', req, { motivo: e.message });
    return res.status(400).render('transferir', { cuenta: await miCuenta(req.session.user.id), form: { destino, monto, descripcion }, error: e.message });
  } finally { c.release(); }
  res.render('transferir', { cuenta: await miCuenta(req.session.user.id), form: {}, ok: 'Transferencia realizada con éxito.' });
}));

// ---------- Perfil ----------
const perfil = async (req, res, extra = {}) => {
  const u = (await pool.query('SELECT nombre, documento, email, creado_en FROM usuarios WHERE id = $1', [req.session.user.id])).rows[0];
  res.render('perfil', { u, cuenta: await miCuenta(req.session.user.id), ...extra });
};
app.get('/perfil', requireAuth, wrap((req, res) => perfil(req, res)));
app.post('/perfil/password', requireAuth, wrap(async (req, res) => {
  const { actual = '', nueva = '', nueva2 = '' } = req.body;
  const u = (await pool.query('SELECT password_hash FROM usuarios WHERE id = $1', [req.session.user.id])).rows[0];
  if (!(await bcrypt.compare(actual, u.password_hash))) { logSeguridad('cambio_password_fallido', req); return perfil(req, res, { error: 'La contraseña actual es incorrecta.' }); }
  if (nueva.length < 10 || !/[a-zA-Z]/.test(nueva) || !/\d/.test(nueva)) return perfil(req, res, { error: 'La nueva contraseña debe tener mínimo 10 caracteres, con letras y números.' });
  if (nueva !== nueva2) return perfil(req, res, { error: 'Las contraseñas nuevas no coinciden.' });
  await pool.query('UPDATE usuarios SET password_hash = $1 WHERE id = $2', [await bcrypt.hash(nueva, 12), req.session.user.id]);
  logSeguridad('cambio_password_exitoso', req);
  perfil(req, res, { ok: 'Contraseña actualizada.' });
}));

app.use((req, res) => res.status(404).send('Página no encontrada'));
app.use((err, req, res, next) => { logSeguridad('error_servidor', req, { mensaje: err.message }); console.error(err); res.status(500).send('Error interno del servidor'); });

pool.ready.then(() => {
  const port = process.env.PORT || 3000;
  const msg = proto => console.log(`Banco Demo en ${proto}://localhost:${port}` + (DEMO ? ' (MODO DEMO: datos en memoria)' : ''));
  if (USE_HTTPS) {
    https.createServer({ key: fs.readFileSync(process.env.SSL_KEY), cert: fs.readFileSync(process.env.SSL_CERT) }, app).listen(port, () => msg('https'));
    // Redirección HTTP -> HTTPS (A02)
    if (process.env.HTTP_REDIRECT_PORT) {
      http.createServer((req, res) => {
        const host = (req.headers.host || 'localhost').replace(/:\d+$/, '');
        res.writeHead(301, { Location: `https://${host}:${port}${req.url}` }); res.end();
      }).listen(process.env.HTTP_REDIRECT_PORT);
    }
  } else {
    app.listen(port, () => msg('http'));
  }
}).catch(e => { console.error('No se pudo preparar la base de datos:', e.message); process.exit(1); });
