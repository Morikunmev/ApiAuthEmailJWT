-- Crear base de datos
CREATE DATABASE IF NOT EXISTS auth_system;
USE auth_system;

-- Tabla de usuarios
CREATE TABLE IF NOT EXISTS usuario (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nombre VARCHAR(100) NOT NULL,
    correo VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    ciudad VARCHAR(100) NOT NULL,
    verificado TINYINT(1) DEFAULT 0,
    token_verificacion VARCHAR(64) DEFAULT NULL,
    fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabla de tokens
CREATE TABLE IF NOT EXISTS tokens (
    id INT AUTO_INCREMENT PRIMARY KEY,
    guid VARCHAR(36) NOT NULL,
    usuario_id INT NOT NULL,
    fecha_creacion DATETIME NOT NULL,
    duracion INT NOT NULL,
    FOREIGN KEY (usuario_id) REFERENCES usuario(id)
);

-- Tabla de usuarios activos
CREATE TABLE IF NOT EXISTS usuario_activo (
    id INT PRIMARY KEY,
    activo TINYINT(1) DEFAULT 1,
    FOREIGN KEY (id) REFERENCES tokens(id)
);
