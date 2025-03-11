<?php
// register.php - Maneja el registro de usuarios y la verificación de correo
header('Content-Type: application/json');
require_once 'config.php';

// Función para el registro de usuarios
function registerUser()
{
    // Solo permitir peticiones POST
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(405);
        echo json_encode(['error' => 'Método no permitido']);
        exit;
    }

    // Obtener datos del cuerpo de la petición
    $data = json_decode(file_get_contents('php://input'), true);

    // Verificar que todos los campos necesarios estén presentes
    $requiredFields = ['nombre', 'correo', 'password', 'confirm_password', 'ciudad'];
    foreach ($requiredFields as $field) {
        if (!isset($data[$field]) || empty($data[$field])) {
            http_response_code(400);
            echo json_encode(['error' => "Campo obligatorio '$field' faltante"]);
            exit;
        }
    }

    // Verificar que las contraseñas coincidan
    if ($data['password'] !== $data['confirm_password']) {
        http_response_code(400);
        echo json_encode(['error' => 'Las contraseñas no coinciden']);
        exit;
    }

    // Verificar formato de correo electrónico
    if (!filter_var($data['correo'], FILTER_VALIDATE_EMAIL)) {
        http_response_code(400);
        echo json_encode(['error' => 'Formato de correo electrónico inválido']);
        exit;
    }

    // Conectar a la base de datos
    $conn = getDbConnection();

    // Verificar si el correo ya está registrado
    $stmt = $conn->prepare("SELECT id FROM usuario WHERE correo = ?");
    $stmt->bind_param("s", $data['correo']);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        http_response_code(409);
        echo json_encode(['error' => 'El correo electrónico ya está registrado']);
        $stmt->close();
        $conn->close();
        exit;
    }

    // Generar hash de la contraseña
    $passwordHash = password_hash($data['password'], PASSWORD_DEFAULT);

    // Generar token de verificación
    $verificationToken = bin2hex(random_bytes(32));

    // Insertar nuevo usuario con estado pendiente de verificación
    $stmt = $conn->prepare("INSERT INTO usuario (nombre, correo, password, ciudad, verificado, token_verificacion) VALUES (?, ?, ?, ?, 0, ?)");
    $stmt->bind_param("sssss", $data['nombre'], $data['correo'], $passwordHash, $data['ciudad'], $verificationToken);

    if ($stmt->execute()) {
        // Enviar correo de verificación
        if (sendVerificationEmail($data['correo'], $verificationToken)) {
            http_response_code(201);
            echo json_encode([
                'message' => 'Usuario registrado correctamente. Se ha enviado un correo de verificación.'
            ]);
        } else {
            http_response_code(500);
            echo json_encode([
                'message' => 'Usuario registrado, pero hubo un problema al enviar el correo de verificación.'
            ]);
        }
    } else {
        http_response_code(500);
        echo json_encode(['error' => 'Error al registrar el usuario: ' . $conn->error]);
    }

    $stmt->close();
    $conn->close();
}

// Función para verificar el correo
function verifyEmail()
{
    // Verificar si hay un token en la URL
    if (!isset($_GET['token']) || empty($_GET['token'])) {
        http_response_code(400);
        echo "Error: Token de verificación faltante.";
        exit;
    }

    $token = $_GET['token'];

    // Conectar a la base de datos
    $conn = getDbConnection();

    // Buscar usuario con este token de verificación
    $stmt = $conn->prepare("SELECT id FROM usuario WHERE token_verificacion = ? AND verificado = 0");
    $stmt->bind_param("s", $token);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows === 0) {
        $stmt->close();
        $conn->close();
        http_response_code(404);
        echo "Error: Token de verificación inválido o ya utilizado.";
        exit;
    }

    $user = $result->fetch_assoc();
    $userId = $user['id'];

    // Actualizar el estado del usuario a verificado
    $updateStmt = $conn->prepare("UPDATE usuario SET verificado = 1, token_verificacion = NULL WHERE id = ?");
    $updateStmt->bind_param("i", $userId);

    if ($updateStmt->execute()) {
        $updateStmt->close();
        $stmt->close();
        $conn->close();

        // Mostrar mensaje de éxito
        echo "
        <!DOCTYPE html>
        <html>
        <head>
            <title>Cuenta Verificada</title>
            <style>
                body { font-family: Arial, sans-serif; text-align: center; margin-top: 50px; }
                .success { color: green; }
            </style>
        </head>
        <body>
            <h1 class='success'>¡Cuenta verificada con éxito!</h1>
            <p>Tu cuenta ha sido verificada correctamente. Ahora puedes iniciar sesión.</p>
        </body>
        </html>";
        exit;
    } else {
        $updateStmt->close();
        $stmt->close();
        $conn->close();
        http_response_code(500);
        echo "Error: No se pudo verificar la cuenta. Inténtelo de nuevo más tarde.";
        exit;
    }
}

// Determinar qué acción realizar
if (isset($_GET['token'])) {
    // Si hay un token en la URL, se trata de una verificación de correo
    verifyEmail();
} else {
    // Si no, se trata de un registro de usuario
    registerUser();
}
?>