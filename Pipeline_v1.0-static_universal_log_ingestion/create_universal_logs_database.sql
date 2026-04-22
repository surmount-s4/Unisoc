-- ============================================================================
-- Universal Log Tool - Database Creation Script
-- ============================================================================
-- 
-- Purpose: Creates a dedicated PostgreSQL database for the Universal Log Tool
-- Database: universal_logs_db
-- 
-- This database is separate from the old real-time pipeline (logs_db) to ensure:
--   - Clean separation of concerns
--   - Independent scaling
--   - No table name conflicts
--   - Easier backup/restore
-- 
-- Usage:
--   psql -U postgres -f create_universal_logs_database.sql
-- 
-- Author: Universal Log Tool Team
-- Date: October 14, 2025
-- ============================================================================

-- Connect to default postgres database to create new database
\c postgres

-- ============================================================================
-- Drop existing database (if recreating)
-- ============================================================================
-- WARNING: Uncomment the following line ONLY if you want to recreate the database
-- This will DELETE ALL DATA in universal_logs_db
-- DROP DATABASE IF EXISTS universal_logs_db;

-- ============================================================================
-- Create Database
-- ============================================================================

CREATE DATABASE universal_logs_db
    WITH 
    OWNER = postgres
    ENCODING = 'UTF8'
    LC_COLLATE = 'en_US.UTF-8'
    LC_CTYPE = 'en_US.UTF-8'
    TABLESPACE = pg_default
    CONNECTION LIMIT = -1
    TEMPLATE template0;

-- Add database comment
COMMENT ON DATABASE universal_logs_db IS 'Universal Log Tool - Parser storage, parsed logs, and correlation results';

-- ============================================================================
-- Grant Permissions
-- ============================================================================

-- Grant all privileges to postgres user
GRANT ALL PRIVILEGES ON DATABASE universal_logs_db TO postgres;

-- If you have other users, grant them permissions here:
-- GRANT CONNECT ON DATABASE universal_logs_db TO your_user;
-- GRANT ALL PRIVILEGES ON DATABASE universal_logs_db TO your_user;

-- ============================================================================
-- Connect to New Database
-- ============================================================================

\c universal_logs_db

-- ============================================================================
-- Enable Extensions (if needed)
-- ============================================================================

-- Enable UUID extension (useful for generating unique IDs)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Enable pg_trgm for faster text search (optional)
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- Enable btree_gin for faster JSONB indexing (optional)
CREATE EXTENSION IF NOT EXISTS btree_gin;

-- ============================================================================
-- Verification
-- ============================================================================

SELECT 'Database Creation Complete!' AS status;
SELECT '=============================' AS separator;

-- Show database info
SELECT 
    datname AS database_name,
    pg_encoding_to_char(encoding) AS encoding,
    datcollate AS collation,
    datctype AS ctype,
    pg_size_pretty(pg_database_size(datname)) AS size
FROM pg_database 
WHERE datname = 'universal_logs_db';

-- Show installed extensions
SELECT extname AS extension_name, extversion AS version
FROM pg_extension
ORDER BY extname;

-- Success message
SELECT 'SUCCESS: Database "universal_logs_db" created and ready!' AS result;
SELECT 'Next Step: Run create_parser_storage_schema.sql to create tables' AS next_step;

-- ============================================================================
-- Next Steps
-- ============================================================================

/*

NEXT STEPS:

1. Create Tables:
   psql -U postgres -d universal_logs_db -f create_parser_storage_schema.sql

2. Update Python Configuration:
   - Update DB_CONFIG in universal_receiver.py
   - Update DB_CONFIG in parser_manager.py
   - Update DB_CONFIG in universal_correlation_engine.py

3. Test Connection:
   psql -U postgres -d universal_logs_db

4. Start Services:
   python universal_receiver.py
   python universal_correlation_engine.py

*/
