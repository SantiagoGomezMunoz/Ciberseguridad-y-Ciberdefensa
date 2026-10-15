-- Esquema PostgreSQL del banco demo
CREATE TABLE IF NOT EXISTS usuarios (
  id                SERIAL PRIMARY KEY,
  nombre            VARCHAR(100) NOT NULL,
  documento         VARCHAR(20)  NOT NULL UNIQUE,
  email             VARCHAR(120) NOT NULL UNIQUE,
  password_hash     TEXT         NOT NULL,
  intentos_fallidos INT          NOT NULL DEFAULT 0,
  bloqueado_hasta   TIMESTAMPTZ,
  creado_en         TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS cuentas (
  id         SERIAL PRIMARY KEY,
  usuario_id INT           NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
  numero     VARCHAR(10)   NOT NULL UNIQUE,
  tipo       VARCHAR(10)   NOT NULL DEFAULT 'ahorros' CHECK (tipo IN ('ahorros','corriente')),
  saldo      NUMERIC(14,2) NOT NULL DEFAULT 0 CHECK (saldo >= 0),
  creado_en  TIMESTAMPTZ   NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS transacciones (
  id             SERIAL PRIMARY KEY,
  cuenta_origen  INT REFERENCES cuentas(id),
  cuenta_destino INT REFERENCES cuentas(id),
  monto          NUMERIC(14,2) NOT NULL CHECK (monto > 0),
  descripcion    VARCHAR(140),
  tipo           VARCHAR(15)   NOT NULL DEFAULT 'transferencia' CHECK (tipo IN ('transferencia','deposito')),
  creado_en      TIMESTAMPTZ   NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_tx_origen  ON transacciones(cuenta_origen);
CREATE INDEX IF NOT EXISTS idx_tx_destino ON transacciones(cuenta_destino);

-- Tabla de sesiones (connect-pg-simple)
CREATE TABLE IF NOT EXISTS session (
  sid    VARCHAR      NOT NULL PRIMARY KEY,
  sess   JSON         NOT NULL,
  expire TIMESTAMP(6) NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_session_expire ON session(expire);
