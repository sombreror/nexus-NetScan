-- NEXUS NetScan v3 — Open Access Schema
-- No auth tables. Logs + rate limits only.
CREATE DATABASE IF NOT EXISTS nexus CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE nexus;

-- Operation logs
CREATE TABLE IF NOT EXISTS logs (
    id          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    created_at  DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    level       ENUM('INFO','WARN','ERROR','SUCCESS') NOT NULL DEFAULT 'INFO',
    tool        VARCHAR(32)     NOT NULL,
    target      VARCHAR(255)    NOT NULL,
    ip          VARCHAR(45)     NOT NULL,
    user_id     BIGINT UNSIGNED NULL,
    result      TEXT,
    duration_ms INT UNSIGNED    NOT NULL DEFAULT 0,
    INDEX idx_created_at      (created_at),
    INDEX idx_level           (level),
    INDEX idx_tool            (tool),
    INDEX idx_ip              (ip),
    INDEX idx_level_tool_date (level, tool, created_at DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Rate limits
CREATE TABLE IF NOT EXISTS rate_limits (
    ip           VARCHAR(45)  NOT NULL PRIMARY KEY,
    requests     INT UNSIGNED NOT NULL DEFAULT 1,
    window_start DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
