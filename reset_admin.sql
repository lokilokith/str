-- SentinelTrace Admin Reset Script
-- Run this against your MySQL server:
--   mysql -u root -p sentinel_live < reset_admin.sql
-- OR paste directly into MySQL Workbench / HeidiSQL

USE sentinel_live;

-- Remove any broken admin account
DELETE FROM analysts WHERE username = 'admin';

-- Insert fresh admin with known-good password hash
INSERT INTO analysts (analyst_id, username, email, role, password_hash, created_at, is_active)
VALUES (
    'USR-ADMIN001',
    'admin',
    'admin@sentineltrace.local',
    'admin',
    'sha256$sentineltrace_fixed_salt_2026$033245214e2367cbecd0a64bf22e2691830e726d47ea12ee0673b3bf01c92bf7',
    NOW(),
    1
);

-- Verify it landed
SELECT analyst_id, username, role, is_active, LEFT(password_hash, 20) AS hash_preview
FROM analysts
WHERE username = 'admin';
