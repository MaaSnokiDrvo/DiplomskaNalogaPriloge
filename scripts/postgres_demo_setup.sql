-- Nastavitev demonstracijske baze PostgreSQL za NetSentinel.
-- Zaženi kot skrbnik PostgreSQL, na primer:
-- psql -h localhost -p 5432 -U postgres -d postgres -f scripts/postgres_demo_setup.sql
--
-- Ustvari ali popravi vlogo in bazo, ki ju uporablja lokalna konfiguracija:
--   user:     netsentinel_user
--   password: nastavi lokalno
--   database: netsentinel_db

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'netsentinel_user') THEN
        CREATE ROLE netsentinel_user LOGIN PASSWORD 'nastavi_lokalno';
    ELSE
        ALTER ROLE netsentinel_user LOGIN PASSWORD 'nastavi_lokalno';
    END IF;
END
$$;

SELECT 'CREATE DATABASE netsentinel_db OWNER netsentinel_user'
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'netsentinel_db')\gexec

ALTER DATABASE netsentinel_db OWNER TO netsentinel_user;

\connect netsentinel_db

GRANT CONNECT ON DATABASE netsentinel_db TO netsentinel_user;
GRANT USAGE, CREATE ON SCHEMA public TO netsentinel_user;

SET ROLE netsentinel_user;
\i scripts/postgres_init.sql
RESET ROLE;

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO netsentinel_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO netsentinel_user;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO netsentinel_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO netsentinel_user;
