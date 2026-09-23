-- ============================================================
-- FILE: admin.sql
-- DESCRIPTION: Database schema, stored procedures, test data, 
--              and selection queries for Admin Management with JWT.
-- ============================================================

-- Enable pgcrypto extension for password hashing (Run if not already enabled)
CREATE EXTENSION IF NOT EXISTS pgcrypto;


-- ============================================================
-- 1. TABLE CREATION
-- ============================================================

-- Table to store Admin details
CREATE TABLE IF NOT EXISTS admins (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) DEFAULT 'ADMIN' NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Table to store JWT sessions and map tokens to Admin IDs
CREATE TABLE IF NOT EXISTS admin_jwt_sessions (
    id SERIAL PRIMARY KEY,
    admin_id INT NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    jwt_token TEXT NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);


-- ============================================================
-- 2. STORED PROCEDURES (FUNCTIONS)
-- ============================================================

-- Function: Register a new Admin
CREATE OR REPLACE FUNCTION register_admin(
    p_username VARCHAR(50),
    p_email VARCHAR(100),
    p_password VARCHAR(255),
    p_confirm_password VARCHAR(255)
) 
RETURNS TABLE(admin_id INT, username VARCHAR(50), email VARCHAR(100), role VARCHAR(20), status_message TEXT) 
LANGUAGE plpgsql AS $$
DECLARE
    v_hashed_password VARCHAR(255);
    v_admin_id INT;
BEGIN
    -- Validate password matching
    IF p_password <> p_confirm_password THEN
        RAISE EXCEPTION 'Password and Confirm Password do not match!';
    END IF;

    -- Check if email already exists
    IF EXISTS (SELECT 1 FROM admins WHERE admins.email = p_email) THEN
        RAISE EXCEPTION 'Admin with email % already exists!', p_email;
    END IF;

    -- Hash the password using Blowfish (bf) algorithm
    v_hashed_password := crypt(p_password, gen_salt('bf', 10));

    -- Insert new Admin into database
    INSERT INTO admins (username, email, password_hash, role)
    VALUES (p_username, p_email, v_hashed_password, 'ADMIN')
    RETURNING id INTO v_admin_id;

    RETURN QUERY 
    SELECT v_admin_id, p_username, p_email, 'ADMIN'::VARCHAR(20), 'Admin registered successfully'::TEXT;
END;
$$;


-- Function: Admin Login & JWT Session Creation
CREATE OR REPLACE FUNCTION login_admin(
    p_email VARCHAR(100),
    p_password VARCHAR(255)
) 
RETURNS TABLE(admin_id INT, email VARCHAR(100), role VARCHAR(20), jwt_token TEXT, expires_at TIMESTAMP WITH TIME ZONE, status_message TEXT) 
LANGUAGE plpgsql AS $$
DECLARE
    v_admin RECORD;
    v_jwt_token TEXT;
    v_expires_at TIMESTAMP WITH TIME ZONE;
BEGIN
    -- Verify Admin existence by email
    SELECT id, admins.username, admins.email, password_hash, admins.role 
    INTO v_admin 
    FROM admins 
    WHERE admins.email = p_email;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Invalid Email or Password!';
    END IF;

    -- Verify password hash
    IF v_admin.password_hash <> crypt(p_password, v_admin.password_hash) THEN
        RAISE EXCEPTION 'Invalid Email or Password!';
    END IF;

    -- Set token expiration time (8 hours from current timestamp)
    v_expires_at := CURRENT_TIMESTAMP + INTERVAL '8 hours';
    
    -- Generate JWT structure token
    v_jwt_token := 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' || 
                   encode(
                       json_build_object(
                           'id', v_admin.id,
                           'email', v_admin.email,
                           'role', v_admin.role,
                           'exp', extract(epoch from v_expires_at)
                       )::text::bytea, 
                       'base64'
                   ) || '.' || 
                   encode(hmac(v_admin.id::text || v_expires_at::text, 'YOUR_JWT_SECRET_KEY', 'sha256'), 'hex');

    -- Store session in JWT mapping table
    INSERT INTO admin_jwt_sessions (admin_id, jwt_token, expires_at)
    VALUES (v_admin.id, v_jwt_token, v_expires_at);

    RETURN QUERY 
    SELECT v_admin.id, v_admin.email, v_admin.role, v_jwt_token, v_expires_at, 'Login successful'::TEXT;
END;
$$;


-- ============================================================
-- 3. DUMMY DATA INSERTION
-- ============================================================

-- Insert sample Admin using the register procedure
SELECT * FROM register_admin('admin_demo', 'admin@example.com', 'AdminPass@123', 'AdminPass@123');

-- Insert sample Admin directly with pre-hashed password
INSERT INTO admins (username, email, password_hash, role)
VALUES ('john_doe', 'john@example.com', crypt('JohnPass@123', gen_salt('bf', 10)), 'ADMIN');


-- ============================================================
-- 4. EXECUTION & SELECTION QUERIES
-- ============================================================

-- Execute Login for the dummy admin
SELECT * FROM login_admin('admin@example.com', 'AdminPass@123');

-- Select all Admins from table
SELECT id, username, email, role, created_at FROM admins;

-- Select all Active JWT Sessions mapped to Admins
SELECT 
    a.id AS admin_id,
    a.username,
    a.email,
    a.role,
    s.jwt_token,
    s.created_at AS session_start,
    s.expires_at AS token_expires_at
FROM admins a
INNER JOIN admin_jwt_sessions s ON a.id = s.admin_id
WHERE s.is_active = TRUE;
