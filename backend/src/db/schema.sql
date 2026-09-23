-- The Watch: Enterprise Multi-Tenant PostgreSQL Schema
-- Timestamps are stored in UTC with timezone; reports render in West Africa Time (WAT)

CREATE TABLE IF NOT EXISTS tenants (
    id VARCHAR(64) PRIMARY KEY,
    system_id VARCHAR(64) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    api_key VARCHAR(128) UNIQUE NOT NULL,
    api_secret VARCHAR(128) NOT NULL,
    primary_contact VARCHAR(255) NOT NULL,
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(64) PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    salt VARCHAR(128) NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    role VARCHAR(32) NOT NULL DEFAULT 'SOC_ANALYST', -- SUPER_ADMIN, SOC_ANALYST, SECURITY_OPERATOR, AUDITOR
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE', -- ACTIVE, SUSPENDED
    allowed_systems VARCHAR(255) DEFAULT 'ALL', -- ALL or comma-separated system_ids
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP WITH TIME ZONE,
    last_login_at TIMESTAMP WITH TIME ZONE,
    last_login_ip VARCHAR(64),
    created_by VARCHAR(255) DEFAULT 'SYSTEM',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS user_audit_logs (
    id VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(64),
    email VARCHAR(255) NOT NULL,
    action VARCHAR(64) NOT NULL, -- LOGIN_SUCCESS, LOGIN_FAILED, ACCOUNT_CREATED, ACCOUNT_SUSPENDED, ACCOUNT_ACTIVATED, ACCOUNT_DELETED
    ip_address VARCHAR(64) NOT NULL,
    user_agent TEXT,
    status VARCHAR(32) NOT NULL DEFAULT 'SUCCESS', -- SUCCESS, FAILED, BLOCKED
    details TEXT,
    created_at_wat VARCHAR(64) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS telemetry_logs (
    id VARCHAR(64) PRIMARY KEY,
    system_id VARCHAR(64) NOT NULL REFERENCES tenants(system_id) ON DELETE CASCADE,
    method VARCHAR(16) NOT NULL,
    path VARCHAR(1024) NOT NULL,
    status_code INTEGER NOT NULL,
    latency_ms DOUBLE PRECISION NOT NULL,
    client_ip VARCHAR(64) NOT NULL,
    payload_snippet TEXT,
    user_agent TEXT,
    headers_json TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS threat_incidents (
    id VARCHAR(64) PRIMARY KEY,
    system_id VARCHAR(64) NOT NULL REFERENCES tenants(system_id) ON DELETE CASCADE,
    incident_type VARCHAR(64) NOT NULL,
    threat_classification VARCHAR(128) NOT NULL,
    severity VARCHAR(32) NOT NULL, -- LOW, MEDIUM, HIGH, CRITICAL
    offending_ip VARCHAR(64) NOT NULL,
    geo_country VARCHAR(128),
    geo_region VARCHAR(128),
    geo_city VARCHAR(128),
    geo_lat DOUBLE PRECISION,
    geo_lng DOUBLE PRECISION,
    asn VARCHAR(128),
    isp VARCHAR(255),
    is_proxy_or_vpn BOOLEAN DEFAULT FALSE,
    target_endpoint VARCHAR(1024) NOT NULL,
    http_method VARCHAR(16) NOT NULL,
    captured_payload TEXT,
    status VARCHAR(32) DEFAULT 'UNRESOLVED', -- UNRESOLVED, ACKNOWLEDGED, RESOLVED
    mitigation_blueprint TEXT,
    remediation_summary TEXT,
    created_at_wat VARCHAR(64) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    acknowledged_by VARCHAR(128),
    resolved_at TIMESTAMP WITH TIME ZONE
);

CREATE TABLE IF NOT EXISTS synthetic_probes (
    id VARCHAR(64) PRIMARY KEY,
    system_id VARCHAR(64) NOT NULL REFERENCES tenants(system_id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    target_url VARCHAR(1024) NOT NULL,
    method VARCHAR(16) DEFAULT 'GET',
    expected_status INTEGER DEFAULT 200,
    interval_seconds INTEGER DEFAULT 30,
    is_enabled BOOLEAN DEFAULT TRUE,
    last_run_at TIMESTAMP WITH TIME ZONE,
    last_status VARCHAR(32) DEFAULT 'PENDING', -- HEALTHY, DEGRADED, DOWN, PENDING
    last_ttfb_ms DOUBLE PRECISION DEFAULT 0,
    last_dns_ms DOUBLE PRECISION DEFAULT 0,
    last_tcp_ms DOUBLE PRECISION DEFAULT 0,
    ssl_expiry_days INTEGER,
    uptime_percent DOUBLE PRECISION DEFAULT 100.0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS probe_history (
    id VARCHAR(64) PRIMARY KEY,
    probe_id VARCHAR(64) NOT NULL REFERENCES synthetic_probes(id) ON DELETE CASCADE,
    system_id VARCHAR(64) NOT NULL,
    status_code INTEGER,
    ttfb_ms DOUBLE PRECISION NOT NULL,
    dns_ms DOUBLE PRECISION NOT NULL,
    tcp_ms DOUBLE PRECISION NOT NULL,
    ssl_valid BOOLEAN DEFAULT TRUE,
    ssl_days_remaining INTEGER,
    is_success BOOLEAN NOT NULL,
    error_message TEXT,
    checked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS database_query_metrics (
    id VARCHAR(64) PRIMARY KEY,
    system_id VARCHAR(64) NOT NULL REFERENCES tenants(system_id) ON DELETE CASCADE,
    query_text TEXT NOT NULL,
    duration_ms DOUBLE PRECISION NOT NULL,
    pool_active_connections INTEGER DEFAULT 0,
    pool_idle_connections INTEGER DEFAULT 0,
    pool_waiting_queries INTEGER DEFAULT 0,
    exceeded_threshold BOOLEAN DEFAULT FALSE, -- queries > 200ms
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_reports (
    id VARCHAR(64) PRIMARY KEY,
    report_title VARCHAR(255) NOT NULL,
    system_id VARCHAR(64) NOT NULL,
    format VARCHAR(16) NOT NULL, -- PDF, CSV
    period_start TIMESTAMP WITH TIME ZONE,
    period_end TIMESTAMP WITH TIME ZONE,
    health_score DOUBLE PRECISION NOT NULL,
    total_incidents INTEGER NOT NULL,
    file_path VARCHAR(1024) NOT NULL,
    generated_at_wat VARCHAR(64) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indices for rapid query observability, users, and incident filtering
CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);
CREATE INDEX IF NOT EXISTS idx_user_audit_time ON user_audit_logs (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_telemetry_system_time ON telemetry_logs (system_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_threat_incidents_system_status ON threat_incidents (system_id, status, severity);
CREATE INDEX IF NOT EXISTS idx_threat_incidents_ip ON threat_incidents (offending_ip);
CREATE INDEX IF NOT EXISTS idx_probe_history_probe_time ON probe_history (probe_id, checked_at DESC);
CREATE INDEX IF NOT EXISTS idx_query_metrics_duration ON database_query_metrics (system_id, duration_ms DESC);
