-- ====================================================================
-- AUTO-RECON AI — MySQL Database & Non-Root Application User Setup
-- Run as MySQL root user or database administrator:
--   mysql -u root -p < backend/setup_mysql.sql
-- ====================================================================

-- 1. Create the database with UTF-8 support
CREATE DATABASE IF NOT EXISTS autorecon_ai 
  CHARACTER SET utf8mb4 
  COLLATE utf8mb4_unicode_ci;

-- 2. Create dedicated non-root application user
-- (Change 'autorecon_secure_password_2026' to your chosen production password)
CREATE USER IF NOT EXISTS 'autorecon_app'@'localhost' 
  IDENTIFIED BY 'autorecon_secure_password_2026';

CREATE USER IF NOT EXISTS 'autorecon_app'@'127.0.0.1' 
  IDENTIFIED BY 'autorecon_secure_password_2026';

-- 3. Grant minimum required application permissions on the autorecon_ai schema
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, INDEX, ALTER, REFERENCES 
  ON autorecon_ai.* TO 'autorecon_app'@'localhost';

GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, INDEX, ALTER, REFERENCES 
  ON autorecon_ai.* TO 'autorecon_app'@'127.0.0.1';

-- 4. Apply privilege changes
FLUSH PRIVILEGES;

-- 5. Verification query
SELECT user, host FROM mysql.user WHERE user = 'autorecon_app';
SHOW GRANTS FOR 'autorecon_app'@'localhost';
