-- Run once against the HeatWave DB System, as the admin user chosen at
-- provisioning time:
--
--   mysql -h <DB_PRIVATE_IP> -u <admin> -p --ssl-mode=REQUIRED < heatwave-setup.sql
--
-- Replace 10.0.0.% with the CIDR of the subnet your VM sits in, and pick a long
-- random password. The host part is not cosmetic: MySQL treats 'ccshare'@'a' and
-- 'ccshare'@'b' as different accounts, and the VM reaches HeatWave from its VCN
-- private address — never from loopback.

CREATE DATABASE IF NOT EXISTS ccshareapp
  CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;

-- REQUIRE SSL makes the server refuse this account over a plaintext connection,
-- so a future misconfigured client fails loudly instead of quietly downgrading.
CREATE USER 'ccshare'@'10.0.0.%'
  IDENTIFIED BY 'CHOOSE_A_LONG_RANDOM_PASSWORD'
  REQUIRE SSL;

-- Flyway creates flyway_schema_history and V3 drops a column, so DDL rights on
-- this schema are needed. Scoped to ccshareapp.* only — the account has no
-- reach outside its own database.
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, DROP, INDEX, REFERENCES
  ON ccshareapp.* TO 'ccshare'@'10.0.0.%';

FLUSH PRIVILEGES;
