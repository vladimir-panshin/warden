CREATE TABLE accounts (
    id             TEXT PRIMARY KEY,
    email          TEXT UNIQUE NOT NULL,
    password_hash  TEXT NOT NULL,
    otp_secret     TEXT,
    recovery_codes TEXT[],
    created_at     TIMESTAMP WITH TIME ZONE DEFAULT now()
);