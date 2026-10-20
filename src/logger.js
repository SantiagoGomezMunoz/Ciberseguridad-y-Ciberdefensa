const fs = require('fs');
const path = require('path');

// Registro de eventos de seguridad (OWASP A09). Escribe JSON por línea en logs/security.log y en consola.
const dir = path.join(__dirname, '..', 'logs');
fs.mkdirSync(dir, { recursive: true });
const stream = fs.createWriteStream(path.join(dir, 'security.log'), { flags: 'a', mode: 0o600 });

// Evita inyección en logs (saltos de línea) y limita la longitud
const limpiar = v => String(v ?? '').replace(/[\r\n\t]+/g, ' ').slice(0, 200);

function logSeguridad(evento, req, extra = {}) {
  const reg = {
    ts: new Date().toISOString(),
    evento,
    ip: req ? limpiar(req.ip) : undefined,
    usuario: req && req.session && req.session.user ? req.session.user.id : undefined,
    ruta: req ? limpiar(req.method + ' ' + req.originalUrl) : undefined,
    ...Object.fromEntries(Object.entries(extra).map(([k, v]) => [k, limpiar(v)]))
  };
  const linea = JSON.stringify(reg);
  stream.write(linea + '\n');
  console.log('[SEGURIDAD]', linea);
}
module.exports = { logSeguridad };
