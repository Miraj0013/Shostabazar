-- ShostaBazar database schema (MySQL 8+)
-- All timestamps are stored in UTC. The app connects with time_zone = '+00:00'.

CREATE TABLE IF NOT EXISTS users (
  id                  INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  username            VARCHAR(30)  NOT NULL UNIQUE,
  email               VARCHAR(254) NOT NULL UNIQUE,
  phone               VARCHAR(20)  NULL,
  password_hash       VARCHAR(100) NOT NULL,              -- bcrypt hash (salted, cost 12)
  role                ENUM('user','admin') NOT NULL DEFAULT 'user',
  is_active           TINYINT(1)   NOT NULL DEFAULT 1,
  totp_secret         VARCHAR(255) NULL,                  -- AES-256-GCM encrypted
  totp_enabled        TINYINT(1)   NOT NULL DEFAULT 0,
  totp_last_step      BIGINT       NULL,                  -- blocks TOTP code replay
  failed_attempts     INT UNSIGNED NOT NULL DEFAULT 0,
  lock_until          DATETIME     NULL,                  -- account lockout
  session_version     INT UNSIGNED NOT NULL DEFAULT 1,    -- bump to kill all sessions
  password_changed_at DATETIME     NULL,
  last_login_at       DATETIME     NULL,
  last_login_ip       VARCHAR(45)  NULL,
  created_at          DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS otp_codes (
  id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id     INT UNSIGNED NOT NULL,
  code_hash   CHAR(64)     NOT NULL,                      -- SHA-256 of the 6-digit code
  purpose     VARCHAR(20)  NOT NULL DEFAULT 'login',
  attempts    INT UNSIGNED NOT NULL DEFAULT 0,
  expires_at  DATETIME     NOT NULL,
  used_at     DATETIME     NULL,
  created_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_otp_user (user_id, purpose),
  CONSTRAINT fk_otp_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS password_resets (
  id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id     INT UNSIGNED NOT NULL,
  token_hash  CHAR(64)     NOT NULL UNIQUE,               -- SHA-256 of the emailed token
  expires_at  DATETIME     NOT NULL,
  used_at     DATETIME     NULL,
  request_ip  VARCHAR(45)  NULL,
  created_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_reset_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS known_devices (
  id           INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id      INT UNSIGNED NOT NULL,
  device_hash  CHAR(64)     NOT NULL,
  device_label VARCHAR(255) NULL,
  ip           VARCHAR(45)  NULL,
  first_seen   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_device (user_id, device_hash),
  CONSTRAINT fk_device_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS audit_logs (
  id          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id     INT UNSIGNED NULL,
  username    VARCHAR(254) NULL,
  event       VARCHAR(40)  NOT NULL,
  ip          VARCHAR(45)  NULL,
  user_agent  VARCHAR(255) NULL,
  details     VARCHAR(500) NULL,
  created_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_audit_event (event),
  INDEX idx_audit_created (created_at),
  INDEX idx_audit_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS products (
  id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  seller_id   INT UNSIGNED  NOT NULL,
  title       VARCHAR(120)  NOT NULL,
  description TEXT          NOT NULL,
  category    VARCHAR(40)   NOT NULL,
  price       DECIMAL(10,2) NOT NULL,
  stock       INT UNSIGNED  NOT NULL DEFAULT 1,
  is_active   TINYINT(1)    NOT NULL DEFAULT 1,
  created_at  DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_products_category (category),
  CONSTRAINT fk_product_seller FOREIGN KEY (seller_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS orders (
  id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  buyer_id    INT UNSIGNED  NOT NULL,
  product_id  INT UNSIGNED  NOT NULL,
  quantity    INT UNSIGNED  NOT NULL,
  unit_price  DECIMAL(10,2) NOT NULL,
  total       DECIMAL(12,2) NOT NULL,
  status      ENUM('placed','shipped','delivered','cancelled') NOT NULL DEFAULT 'placed',
  created_at  DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_order_buyer   FOREIGN KEY (buyer_id)   REFERENCES users(id)    ON DELETE CASCADE,
  CONSTRAINT fk_order_product FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Development-only outbox so OTPs / reset links can be demonstrated without real SMTP/SMS.
CREATE TABLE IF NOT EXISTS dev_mailbox (
  id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  channel     ENUM('email','sms') NOT NULL DEFAULT 'email',
  recipient   VARCHAR(254) NOT NULL,
  subject     VARCHAR(200) NULL,
  body        TEXT         NOT NULL,
  action_url  VARCHAR(500) NULL,
  created_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
