// Arranca la app sin PostgreSQL (funciona igual en Windows, macOS y Linux)
process.env.DEMO_MODE = 'true';
require('../src/server.js');
