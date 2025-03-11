<?php
// login.php - Endpoint para inicio de sesión
header('Content-Type: application/json');
require_once 'config.php';

// Solo permitir peticiones POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Método no permitido']);
    exit;
}

// Obtener datos del cuerpo de la petición
$data = json_decode(file_get_contents('php://input'), true);

// Verificar que todos los campos necesarios estén presentes
if (!isset($data['correo']) || !isset($data['password'])) {
    http_response_code(400);
    echo json_encode(['error' => 'Correo y contraseña son requeridos']);
    exit;
}

// Conectar a la base de datos
$conn = getDbConnection();

// Buscar usuario por correo
$stmt = $conn->prepare("SELECT id, nombre, correo, password, verificado FROM usuario WHERE correo = ?");
$stmt->bind_param("s", $data['correo']);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows === 0) {
    http_response_code(401);
    echo json_encode(['error' => 'Credenciales inválidas']);
    $stmt->close();
    $conn->close();
    exit;
}

$user = $result->fetch_assoc();

// Verificar si el usuario ha confirmado su correo
if ($user['verificado'] != 1) {
    http_response_code(403);
    echo json_encode(['error' => 'Cuenta no verificada. Por favor, verifique su correo electrónico.']);
    $stmt->close();
    $conn->close();
    exit;
}

// Verificar contraseña
if (!password_verify($data['password'], $user['password'])) {
    http_response_code(401);
    echo json_encode(['error' => 'Credenciales inválidas']);
    $stmt->close();
    $conn->close();
    exit;
}

// Generar token JWT
$jwt = generateJWT($user['id']);

// Guardar token en la base de datos
// Generar GUID para el token
$guid = sprintf('%04X%04X-%04X-%04X-%04X-%04X%04X%04X', 
    mt_rand(0, 65535), mt_rand(0, 65535), mt_rand(0, 65535), 
    mt_rand(16384, 20479), mt_rand(32768, 49151), 
    mt_rand(0, 65535), mt_rand(0, 65535), mt_rand(0, 65535));

// Insertar el token en la tabla tokens
$tokenStmt = $conn->prepare("INSERT INTO tokens (guid, usuario_id, fecha_creacion, duracion) VALUES (?, ?, NOW(), ?)");
$duracion = 24; // 24 horas
$tokenStmt->bind_param("sii", $guid, $user['id'], $duracion);
$tokenStmt->execute();

// Obtener el ID del token recién insertado
$tokenId = $conn->insert_id;

// Insertar en la tabla usuario_activo
$activoStmt = $conn->prepare("INSERT INTO usuario_activo (id, activo) VALUES (?, 1)");
$activoStmt->bind_param("i", $tokenId);
$activoStmt->execute();

$tokenStmt->close();
$activoStmt->close();
$stmt->close();
$conn->close();

// Devolver respuesta exitosa con token
echo json_encode([
    'success' => true,
    'message' => 'Inicio de sesión exitoso',
    'token' => $jwt,
    'usuario' => [
        'id' => $user['id'],
        'nombre' => $user['nombre'],
        'correo' => $user['correo']
    ]
]);
?>