-- SmartEnergy -- Postgres init schema
-- Loaded automatically on first container start via docker-entrypoint-initdb.d

CREATE TABLE IF NOT EXISTS telemetry (
    id          SERIAL PRIMARY KEY,
    ts          TIMESTAMPTZ NOT NULL DEFAULT now(),
    source      VARCHAR(64)  NOT NULL,
    component   VARCHAR(32)  NOT NULL,
    key         VARCHAR(64)  NOT NULL,
    value       DOUBLE PRECISION NOT NULL,
    unit        VARCHAR(16)  NOT NULL DEFAULT '',
    severity    VARCHAR(16)  NOT NULL DEFAULT 'low'
);

CREATE INDEX IF NOT EXISTS idx_telemetry_ts ON telemetry (ts DESC);

-- Seed a few rows so backup is never empty
INSERT INTO telemetry (source, component, key, value, unit) VALUES
    ('meter-17',    'edge',    'voltage',      230.5,  'V'),
    ('meter-22',    'edge',    'power_kw',      12.3,  'kW'),
    ('inverter-01', 'edge',    'frequency_hz',  50.01, 'Hz'),
    ('db-primary',  'db',      'connections',    5,    'count'),
    ('collector-01','edge',    'temperature_c', 42.7,  'C');

-- A control table for integrity checks after restore
CREATE TABLE IF NOT EXISTS integrity_check (
    id      SERIAL PRIMARY KEY,
    marker  VARCHAR(64) NOT NULL DEFAULT 'healthy',
    updated TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO integrity_check (marker) VALUES ('healthy');
