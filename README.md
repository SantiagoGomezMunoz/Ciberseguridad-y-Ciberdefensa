# Banco Demo

Aplicación web bancaria de demostración (proyecto académico) con Node.js, Express, EJS y PostgreSQL.

## Funcionalidades
- Registro e inicio de sesión (contraseñas con bcrypt, bloqueo de 15 min tras 5 intentos fallidos, límite de peticiones)
- Panel con saldo y últimos movimientos
- Transferencias entre cuentas con transacciones SQL atómicas (`BEGIN/COMMIT`, bloqueo de filas)
- Historial de movimientos con paginación
- Perfil y cambio de contraseña
- Sesiones guardadas en PostgreSQL, expiran a los 15 min de inactividad
- Protección CSRF, consultas parametrizadas, cabeceras de seguridad (Helmet)

Cada usuario nuevo recibe una cuenta con 1.000.000 COP de saldo de bienvenida para poder probar transferencias.

## Ejecutar solo la página (modo demo, sin PostgreSQL)
Útil mientras la base de datos real no está lista. Usa una base de datos emulada en memoria: los datos se borran al apagar el servidor.
```bash
npm install
npm run demo
```
Abrir http://localhost:3000, crear una cuenta en "Regístrate" e iniciar sesión.

## Ejecutar con PostgreSQL real
## Requisitos
- Node.js 18 o superior
- PostgreSQL 13 o superior

## Instalación
```bash
git clone <URL-DEL-REPOSITORIO>
cd banco-web
npm install
```

1. Crear la base de datos y el usuario:
```sql
CREATE USER banco_user WITH PASSWORD 'cambia_esta_clave';
CREATE DATABASE banco_db OWNER banco_user;
```
2. Copiar la configuración y editarla:
```bash
cp .env.example .env
```
3. Crear las tablas:
```bash
psql "postgresql://banco_user:cambia_esta_clave@localhost:5432/banco_db" -f db/schema.sql
```
4. Iniciar:
```bash
npm start        # o npm run dev para recarga automática
```
Abrir http://localhost:3000

## Despliegue (resumen)
- Ejecutar con systemd o PM2 detrás de Nginx/Apache como proxy inverso con HTTPS.
- En `.env` poner `COOKIE_SECURE=true` y `TRUST_PROXY=true`.
- Nunca subir `.env` al repositorio (ya está en `.gitignore`).

## Estructura
```
src/server.js   rutas y lógica
src/db.js       conexión a PostgreSQL
db/schema.sql   tablas
views/          plantillas EJS
public/         estilos
```
