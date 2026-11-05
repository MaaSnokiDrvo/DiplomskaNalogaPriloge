-- Shema PostgreSQL za demonstracijsko in analitično hrambo NetSentinel IDS.
-- Zaledje C++ zapisuje simulirane demonstracijske incidente v tabelo incidents,
-- če je zgrajeno z libpq in je POSTGRES_ENABLED=1. Pythonova analitika lahko
-- ob omogočenem PostgreSQL uporablja tudi tabele threats, flows in alerts.

CREATE TABLE IF NOT EXISTS threats (
    threat_id SERIAL PRIMARY KEY,
    src_ip INET,
    dst_ip INET,
    dst_port INTEGER,
    protocol VARCHAR(10),
    threat_level VARCHAR(20),
    threat_score REAL,
    ml_score REAL,
    anomaly_score REAL,
    behavioral_score REAL,
    indicators TEXT,
    recommendation TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved BOOLEAN DEFAULT FALSE,
    tags TEXT
);

CREATE INDEX IF NOT EXISTS idx_threats_timestamp ON threats (timestamp);
CREATE INDEX IF NOT EXISTS idx_threats_level ON threats (threat_level);
CREATE INDEX IF NOT EXISTS idx_threats_src_ip ON threats (src_ip);

CREATE TABLE IF NOT EXISTS flows (
    flow_id SERIAL PRIMARY KEY,
    src_ip INET,
    dst_ip INET,
    src_port INTEGER,
    dst_port INTEGER,
    protocol VARCHAR(10),
    bytes_sent BIGINT,
    bytes_recv BIGINT,
    packets BIGINT,
    duration_sec REAL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    threat_score REAL,
    anomaly_score REAL,
    entropy REAL
);

CREATE INDEX IF NOT EXISTS idx_flows_timestamp ON flows (timestamp);
CREATE INDEX IF NOT EXISTS idx_flows_src_ip ON flows (src_ip);
CREATE INDEX IF NOT EXISTS idx_flows_dst_ip ON flows (dst_ip);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id SERIAL PRIMARY KEY,
    threat_id INTEGER REFERENCES threats(threat_id),
    alert_type VARCHAR(50),
    severity VARCHAR(20),
    message TEXT,
    triggered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    acknowledged BOOLEAN DEFAULT FALSE,
    ack_user VARCHAR(50),
    ack_time TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity);
CREATE INDEX IF NOT EXISTS idx_alerts_triggered_at ON alerts (triggered_at);

CREATE TABLE IF NOT EXISTS incidents (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    src_ip INET,
    src_port INTEGER,
    dst_ip INET,
    dst_port INTEGER,
    protocol INTEGER,
    anomaly_score REAL,
    incident_type VARCHAR(80),
    severity VARCHAR(20),
    description TEXT,
    status VARCHAR(20) DEFAULT 'open',
    notes TEXT
);

CREATE INDEX IF NOT EXISTS idx_incidents_timestamp ON incidents (timestamp);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents (severity);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents (status);
CREATE INDEX IF NOT EXISTS idx_incidents_src_ip ON incidents (src_ip);

CREATE TABLE IF NOT EXISTS analytics_hourly (
    hour TIMESTAMP PRIMARY KEY,
    total_flows BIGINT,
    total_threats INTEGER,
    critical_count INTEGER,
    high_count INTEGER,
    medium_count INTEGER,
    unique_src_ips INTEGER,
    unique_dst_ips INTEGER,
    avg_threat_score REAL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    event_type VARCHAR(50),
    component VARCHAR(100),
    message TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log (timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_log_event_type ON audit_log (event_type);
