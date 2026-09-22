CREATE TABLE admin (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    confirm_password VARCHAR(255) NOT NULL
);
SELECT * FROM admin;
INSERT INTO admin (username, email, password,confirm_password)
VALUES ('admin1','admin@example.com','admin@123','admin@123');
SELECT * FROM admin;