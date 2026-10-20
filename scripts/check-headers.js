// Verifica las cabeceras de seguridad de la app en ejecución (sin dependencias).
// Uso: npm run check   (o: node scripts/check-headers.js http://localhost:3000)
const base = process.argv[2] || 'http://localhost:3000';
const rutas = ['/login', '/register', '/robots.txt', '/sitemap.xml'];
(async () => {
  let fallos = 0;
  for (const r of rutas) {
    const res = await fetch(base + r, { redirect: 'manual' });
    const csp = res.headers.get('content-security-policy') || '';
    const cookie = res.headers.get('set-cookie') || '';
    const prob = [];
    if (!csp) prob.push('sin CSP');
    if (/unsafe-inline|unsafe-eval/.test(csp)) prob.push('CSP con unsafe-inline/unsafe-eval');
    if (/(^|[\s;])(https?:|data:|\*)(\s|;|$)/.test(csp)) prob.push('CSP con comodín / https: / data:');
    for (const d of ['default-src','script-src','style-src','img-src','font-src','frame-src','form-action','frame-ancestors','object-src','base-uri'])
      if (!new RegExp('(^|;)\\s*' + d + '\\s').test(csp)) prob.push('falta ' + d);
    if (res.headers.get('x-powered-by')) prob.push('expone X-Powered-By');
    if (/connect\.sid/.test(cookie)) prob.push('cookie con nombre por defecto (versión vieja del código)');
    if (base.startsWith('https') && cookie && !/secure/i.test(cookie)) prob.push('cookie sin Secure');
    console.log((prob.length ? 'FALLA ' : 'OK    ') + r + (prob.length ? ' -> ' + prob.join('; ') : ''));
    fallos += prob.length;
  }
  console.log(fallos ? '\nHay ' + fallos + ' problema(s): probablemente se está ejecutando código viejo.' : '\nCabeceras correctas.');
  process.exit(fallos ? 1 : 0);
})().catch(e => { console.error('No se pudo conectar a', base, '-', e.message); process.exit(2); });
