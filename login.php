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
if (!isset($data['email']) || !isset($data['password'])) {
    http_response_code(400);
    echo json_encode(['error' => 'Email y contraseña son requeridos']);
    exit;
}

// Conectar a la base de datos
$conn = getDbConnection();

// Buscar usuario por email
$stmt = $conn->prepare("SELECT id, email, password, status FROM usuarios WHERE email = ?");
$stmt->bind_param("s", $data['email']);
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

// Verificar si el usuario está activo
if ($user['status'] !== 'active') {
    http_response_code(403);
    echo json_encode(['error' => 'Cuenta no verificada o suspendida. Por favor, verifique su correo electrónico.']);
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
$guid = sprintf(
    '%04X%04X-%04X-%04X-%04X-%04X%04X%04X',
    mt_rand(0, 65535),
    mt_rand(0, 65535),
    mt_rand(0, 65535),
    mt_rand(16384, 20479),
    mt_rand(32768, 49151),
    mt_rand(0, 65535),
    mt_rand(0, 65535),
    mt_rand(0, 65535)
);

// Duración de la sesión en horas
$duracion = 24; // 24 horas por defecto

// Insertar el token en la tabla tokens con estado activo
$tokenStmt = $conn->prepare("INSERT INTO tokens (guid, usuario_id, fecha_creacion, activo) VALUES (?, ?, NOW(), 1)");
$tokenStmt->bind_param("si", $guid, $user['id']);
$tokenStmt->execute();

// Obtener el ID del token recién insertado
$tokenId = $conn->insert_id;

// Capturar información adicional sobre el login
$ipAddress = $_SERVER['REMOTE_ADDR'] ?? null;
$userAgent = $_SERVER['HTTP_USER_AGENT'] ?? null;

// Insertar en la tabla logins
$loginStmt = $conn->prepare("INSERT INTO logins (token_id, inicio_sesion, duracion_horas, ip_address, user_agent) VALUES (?, NOW(), ?, ?, ?)");
$loginStmt->bind_param("iiss", $tokenId, $duracion, $ipAddress, $userAgent);
$loginStmt->execute();

$tokenStmt->close();
$loginStmt->close();
$stmt->close();
$conn->close();

// Calcular tiempo de expiración para el frontend
$expiracion = time() + ($duracion * 3600); // Convertir horas a segundos

// Devolver respuesta exitosa con token
echo json_encode([
    'success' => true,
    'message' => 'Inicio de sesión exitoso',
    'token' => $jwt,
    'expira_en' => $duracion * 3600, // Segundos hasta expiración
    'expira_fecha' => date('Y-m-d H:i:s', $expiracion), // Fecha/hora de expiración
    'usuario' => [
        'id' => $user['id'],
        'email' => $user['email']
    ]
]);
