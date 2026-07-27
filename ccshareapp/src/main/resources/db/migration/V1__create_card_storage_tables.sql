CREATE TABLE cards (
    card_identifier CHAR(36) NOT NULL,
    encrypted_cc_blob VARBINARY(512) NOT NULL,
    srp_verifier VARCHAR(512) NOT NULL,
    srp_salt VARCHAR(64) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    failed_attempt_count SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    locked_until TIMESTAMP NULL DEFAULT NULL,
    PRIMARY KEY (card_identifier)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE card_auth_events (
    event_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    card_identifier CHAR(36) NOT NULL,
    event_type ENUM('fetch_fail', 'fetch_success', 'authlink_fail', 'authlink_success', 'lockout_triggered') NOT NULL,
    occurred_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    client_ip_hash CHAR(64) NULL,
    PRIMARY KEY (event_id),
    INDEX idx_card_identifier_occurred_at (card_identifier, occurred_at),
    INDEX idx_event_type_occurred_at (event_type, occurred_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
