DROP TABLE IF EXISTS users;
CREATE TABLE users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    phone_number TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'user'
);

DROP TABLE IF EXISTS models;
CREATE TABLE models (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    author TEXT NOT NULL,
    likes INTEGER DEFAULT 0,
    image_url TEXT NOT NULL,
    category TEXT DEFAULT 'Art',
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

DROP TABLE IF EXISTS orders;
CREATE TABLE orders (
    id TEXT PRIMARY KEY,
    model_id TEXT NOT NULL,
    buyer_username TEXT NOT NULL,
    slip_image TEXT NOT NULL, /* 👈 เพิ่มช่องเก็บ Base64 รูปสลิป */
    status TEXT DEFAULT 'pending', /* 👈 สถานะเริ่มต้นคือ รอแอดมินตรวจ */
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);