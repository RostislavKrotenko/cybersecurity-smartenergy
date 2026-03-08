-- SmartEnergy -- Postgres init schema
-- Loaded automatically on first container start via docker-entrypoint-initdb.d

-- Telemetry table: stores sensor readings and device metrics
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
CREATE INDEX IF NOT EXISTS idx_telemetry_source ON telemetry (source);
CREATE INDEX IF NOT EXISTS idx_telemetry_component ON telemetry (component);

-- Seed telemetry rows so backup is never empty
INSERT INTO telemetry (source, component, key, value, unit) VALUES
    ('meter-17',    'edge',    'voltage',      230.5,  'V'),
    ('meter-22',    'edge',    'power_kw',      12.3,  'kW'),
    ('inverter-01', 'edge',    'frequency_hz',  50.01, 'Hz'),
    ('db-primary',  'db',      'connections',    5,    'count'),
    ('collector-01','edge',    'temperature_c', 42.7,  'C'),
    ('meter-17',    'edge',    'voltage',      229.8,  'V'),
    ('meter-22',    'edge',    'power_kw',      11.9,  'kW'),
    ('inverter-02', 'edge',    'frequency_hz',  50.02, 'Hz');

-- Control state table: runtime configuration key-value store
CREATE TABLE IF NOT EXISTS control_state (
    key         VARCHAR(128) PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_ts  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Seed control_state with default values
INSERT INTO control_state (key, value) VALUES
    ('rate_limit_enabled', 'false'),
    ('rate_limit_rps', '100'),
    ('rate_limit_burst', '200'),
    ('isolation_mode', 'none'),
    ('backup_schedule', 'hourly'),
    ('last_backup_ts', 'never'),
    ('network_latency_ms', '0'),
    ('network_drop_rate', '0.0');

-- Integrity check table: marker for DB health verification after restore
CREATE TABLE IF NOT EXISTS integrity_check (
    id      SERIAL PRIMARY KEY,
    marker  VARCHAR(64) NOT NULL DEFAULT 'healthy',
    updated TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO integrity_check (marker) VALUES ('healthy');

-- Helper function to check integrity
CREATE OR REPLACE FUNCTION check_integrity()
RETURNS TABLE(healthy BOOLEAN, marker_value VARCHAR, row_count BIGINT) AS $$
BEGIN
    RETURN QUERY
    SELECT
        ic.marker = 'healthy' AS healthy,
        ic.marker AS marker_value,
        (SELECT COUNT(*) FROM telemetry) AS row_count
    FROM integrity_check ic
    LIMIT 1;
END;
$$ LANGUAGE plpgsql;
