-- Crear base de datos
CREATE DATABASE IF NOT EXISTS auth_system;
USE auth_system;

CREATE TABLE IF NOT EXISTS usuarios (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nombre VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    ciudad VARCHAR(100) NOT NULL,
    status ENUM('pending', 'active', 'suspended') DEFAULT 'pending',
    token_verificacion VARCHAR(64) DEFAULT NULL,
    fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabla de tokens
CREATE TABLE IF NOT EXISTS tokens (
    id INT AUTO_INCREMENT PRIMARY KEY,
    guid VARCHAR(36) NOT NULL,
    usuario_id INT NOT NULL,
    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    activo TINYINT(1) DEFAULT 1,
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
);

-- Tabla de logins
CREATE TABLE IF NOT EXISTS logins (
    id INT AUTO_INCREMENT PRIMARY KEY,
    token_id INT NOT NULL,
    inicio_sesion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    duracion_horas INT DEFAULT 24,
    user_agent TEXT,
    FOREIGN KEY (token_id) REFERENCES tokens(id)
);	