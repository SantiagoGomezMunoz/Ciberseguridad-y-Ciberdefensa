// Llena la base de datos con datos ficticios: 200 usuarios + 200 cuentas + 1000 transacciones (1.400 registros)
// Uso: npm run db:seed            (PostgreSQL real, usa DATABASE_URL)
//      npm run db:seed -- --demo  (base en memoria, solo para probar el script)
if (process.argv.includes('--demo')) process.env.DEMO_MODE = 'true';
const bcrypt = require('bcryptjs');
const pool = require('../src/db');

const N_USUARIOS = 200;
const N_TX = 1000;
const NOMBRES = ['Santiago', 'Valentina', 'Mateo', 'Camila', 'Sebastián', 'Daniela', 'Juan', 'Laura', 'Andrés', 'Mariana', 'Carlos', 'Paula', 'Felipe', 'Sofía', 'David', 'Isabella', 'Nicolás', 'Natalia', 'Julián', 'Carolina'];
const APELLIDOS = ['Gómez', 'Rodríguez', 'Martínez', 'López', 'García', 'Hernández', 'Pérez', 'Ramírez', 'Torres', 'Díaz', 'Vargas', 'Castro', 'Rojas', 'Moreno', 'Muñoz', 'Ortiz'];
const DESCRIPCIONES = ['Pago arriendo', 'Mercado', 'Cuota préstamo', 'Regalo', 'Pago servicios', 'Transporte', 'Almuerzo', 'Ahorro', 'Pago matrícula', 'Reembolso'];
const rnd = (n) => Math.floor(Math.random() * n);
const pick = (a) => a[rnd(a.length)];
const sinTildes = (s) => s.normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase();

(async () => {
  await pool.ready;
  // Un solo hash para todos (bcrypt es lento); contraseña de prueba: Demo1234!
  const hash = await bcrypt.hash('Demo1234!', 10);
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    const cuentas = [];
    for (let i = 0; i < N_USUARIOS; i++) {
      const nombre = `${pick(NOMBRES)} ${pick(APELLIDOS)} ${pick(APELLIDOS)}`;
      const documento = String(1000000000 + i * 7919 + rnd(7000)); // único por construcción
      const email = `${sinTildes(nombre).replace(/\s+/g, '.')}.${i}@demo.com`;
      const u = await c.query('INSERT INTO usuarios (nombre, documento, email, password_hash) VALUES ($1,$2,$3,$4) RETURNING id', [nombre, documento, email, hash]);
      const numero = String(2000000000 + i * 3571 + rnd(3000));
      const tipo = Math.random() < 0.8 ? 'ahorros' : 'corriente';
      const saldo = (1 + rnd(5000)) * 1000;
      const r = await c.query('INSERT INTO cuentas (usuario_id, numero, tipo, saldo) VALUES ($1,$2,$3,$4) RETURNING id', [u.rows[0].id, numero, tipo, saldo]);
      cuentas.push(r.rows[0].id);
    }
    for (let i = 0; i < N_TX; i++) {
      const origen = pick(cuentas);
      let destino = pick(cuentas);
      while (destino === origen) destino = pick(cuentas);
      const monto = (1 + rnd(500)) * 1000;
      const fecha = new Date(Date.now() - rnd(180 * 24 * 3600 * 1000)); // últimos 6 meses
      await c.query('INSERT INTO transacciones (cuenta_origen, cuenta_destino, monto, descripcion, creado_en) VALUES ($1,$2,$3,$4,$5)', [origen, destino, monto, pick(DESCRIPCIONES), fecha]);
    }
    await c.query('COMMIT');
    for (const t of ['usuarios', 'cuentas', 'transacciones']) {
      console.log(t, (await pool.query(`SELECT count(*) FROM ${t}`)).rows[0].count);
    }
  } catch (e) {
    await c.query('ROLLBACK');
    console.error('Error:', e.message);
    process.exitCode = 1;
  } finally {
    c.release();
    await pool.end();
  }
})();
