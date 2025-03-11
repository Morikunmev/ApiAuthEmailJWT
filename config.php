<?php
// config.php - Configuración de la base de datos y JWT

// Cargar variables de entorno
$envFile = null;
$possibleEnvPaths = [
    __DIR__ . '/.env',                      // Mismo directorio
    dirname(__DIR__) . '/.env',             // Directorio padre
    dirname(dirname(__DIR__)) . '/.env',    // Dos niveles arriba
    $_SERVER['DOCUMENT_ROOT'] . '/.env',    // Raíz del documento
];

foreach ($possibleEnvPaths as $path) {
    if (file_exists($path)) {
        $envFile = $path;
        break;
    }
}

// Cargar variables desde .env
if ($envFile) {
    $lines = file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        if (strpos(trim($line), '#') === 0 || strpos($line, '=') === false) continue;
        list($key, $value) = explode('=', $line, 2);
        $_ENV[trim($key)] = trim(trim($value), '"');
    }
}

// Función para obtener variables de entorno
function env($key)
{
    return $_ENV[$key] ?? null;
}

// Definir constantes
define('DB_HOST', env('DB_HOST'));
define('DB_USER', env('DB_USER'));
define('DB_PASS', env('DB_PASS'));
define('DB_NAME', env('DB_NAME'));
define('DB_PORT', env('DB_PORT'));
define('SITE_URL', env('SITE_URL'));
define('APP_NAME', env('APP_NAME'));
define('JWT_SECRET', env('JWT_SECRET'));
define('JWT_EXPIRY', env('JWT_EXPIRY'));

// Conexión a la base de datos
function getDbConnection()
{
    $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME, DB_PORT);
    if ($conn->connect_error) {
        die("Error de conexión: " . $conn->connect_error);
    }
    $conn->set_charset("utf8");
    return $conn;
}

// Función para generar tokens JWT
function generateJWT($user_id)
{
    $issuedAt = time();
    $expiryTime = $issuedAt + JWT_EXPIRY;

    $payload = [
        'iat' => $issuedAt,
        'exp' => $expiryTime,
        'user_id' => $user_id
    ];

    $header = json_encode(['typ' => 'JWT', 'alg' => 'HS256']);
    $header = base64_encode($header);

    $payload = json_encode($payload);
    $payload = base64_encode($payload);

    $signature = hash_hmac('sha256', "$header.$payload", JWT_SECRET, true);
    $signature = base64_encode($signature);

    return "$header.$payload.$signature";
}

// Función para verificar tokens JWT
function verifyJWT($token)
{
    $parts = explode('.', $token);
    if (count($parts) != 3) return false;

    list($header, $payload, $signature) = $parts;
    $verifySignature = base64_encode(hash_hmac('sha256', "$header.$payload", JWT_SECRET, true));

    if ($signature !== $verifySignature) return false;

    $payload = json_decode(base64_decode($payload), true);
    if ($payload['exp'] < time()) return false;

    return $payload;
}

// Función para validar autenticación
function authenticateUser()
{
    // Obtener el encabezado de autorización
    $headers = null;
    if (isset($_SERVER['Authorization'])) {
        $headers = trim($_SERVER['Authorization']);
    } else if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
        $headers = trim($_SERVER['HTTP_AUTHORIZATION']);
    } else if (function_exists('apache_request_headers')) {
        $requestHeaders = apache_request_headers();
        $requestHeaders = array_combine(
            array_map('ucwords', array_keys($requestHeaders)),
            array_values($requestHeaders)
        );
        if (isset($requestHeaders['Authorization'])) {
            $headers = trim($requestHeaders['Authorization']);
        }
    }

    // Extraer el token
    $token = null;
    if (!empty($headers) && preg_match('/Bearer\s(\S+)/', $headers, $matches)) {
        $token = $matches[1];
    }

    if (!$token) {
        header('Content-Type: application/json');
        http_response_code(401);
        echo json_encode(['error' => 'Token de autenticación no proporcionado', 'code' => 'token_missing']);
        exit;
    }

    // Verificar token JWT
    $payload = verifyJWT($token);
    if (!$payload) {
        header('Content-Type: application/json');
        http_response_code(401);
        echo json_encode(['error' => 'Token inválido o expirado', 'code' => 'token_invalid']);
        exit;
    }

    // Verificar si el token está activo en la base de datos
    $conn = getDbConnection();
    $stmt = $conn->prepare("
        SELECT t.id, t.activo, l.inicio_sesion, l.duracion_horas
        FROM tokens t 
        JOIN logins l ON t.id = l.token_id 
        WHERE t.usuario_id = ? AND t.activo = 1 
        AND l.inicio_sesion > DATE_SUB(NOW(), INTERVAL l.duracion_horas HOUR)
    ");

    $stmt->bind_param("i", $payload['user_id']);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows === 0) {
        $stmt->close();
        $conn->close();
        header('Content-Type: application/json');
        http_response_code(401);
        echo json_encode([
            'error' => 'Sesión inválida o expirada',
            'code' => 'session_expired',
            'message' => 'Tu sesión ha expirado. Por favor, inicia sesión nuevamente.'
        ]);
        exit;
    }

    // Obtener información de la sesión
    $sessionInfo = $result->fetch_assoc();

    $stmt->close();
    $conn->close();

    return [
        'user_id' => $payload['user_id'],
        'token_id' => $sessionInfo['id']
    ];
}

// Función para cerrar sesión (invalidar token)
function logout($tokenId = null)
{
    if (!$tokenId) {
        $auth = authenticateUser();
        $tokenId = $auth['token_id'];
    }

    $conn = getDbConnection();
    $stmt = $conn->prepare("UPDATE tokens SET activo = 0 WHERE id = ?");
    $stmt->bind_param("i", $tokenId);
    $result = $stmt->execute();

    $stmt->close();
    $conn->close();

    return $result;
}
// Función simple para enviar correos (versión mínima)
// Función para enviar correos con PHPMailer
function sendVerificationEmail($email, $token)
{
    // Verificar si existe el autoloader de Composer
    $autoloaderPaths = [
        __DIR__ . '/vendor/autoload.php',
        __DIR__ . '/../vendor/autoload.php',
        dirname(__DIR__) . '/vendor/autoload.php'
    ];

    $autoloaderFound = false;
    foreach ($autoloaderPaths as $path) {
        if (file_exists($path)) {
            require_once $path;
            $autoloaderFound = true;
            break;
        }
    }

    // Si no se encuentra el autoloader o PHPMailer, usar función mail() nativa
    if (!$autoloaderFound || !class_exists('PHPMailer\PHPMailer\PHPMailer')) {
        // Método alternativo usando mail() nativo
        $subject = "Verificación de cuenta";
        $verificationLink = SITE_URL . "/register.php?token=" . $token;

        $message = "Hola,\n\n";
        $message .= "Gracias por registrarte. Por favor, verifica tu cuenta haciendo clic en el siguiente enlace:\n";
        $message .= $verificationLink . "\n\n";
        $message .= "Este enlace expirará en 24 horas.\n\n";
        $message .= "Saludos,\nEl equipo de " . APP_NAME;

        $headers = "From: no-reply@" . parse_url(SITE_URL, PHP_URL_HOST) . "\r\n";

        return mail($email, $subject, $message, $headers);
    }

    // Usar PHPMailer
    try {
        $mail = new PHPMailer\PHPMailer\PHPMailer(true);

        // Configuración del servidor
        $mail->isSMTP();
        $mail->Host       = env('MAIL_HOST');
        $mail->SMTPAuth   = true;
        $mail->Username   = env('MAIL_USERNAME');
        $mail->Password   = env('MAIL_PASSWORD');
        $mail->SMTPSecure = env('MAIL_ENCRYPTION') === 'ssl'
            ? PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_SMTPS
            : PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port       = env('MAIL_PORT');

        // Remitentes y destinatarios
        $mail->setFrom(env('MAIL_FROM'), APP_NAME);
        $mail->addAddress($email);

        // Contenido
        $mail->isHTML(true);
        $verificationLink = SITE_URL . "/register.php?token=" . $token;

        $mail->Subject = 'Verificación de cuenta';
        $mail->Body    = "
            <html>
            <head>
                <style>
                    body { font-family: Arial, sans-serif; line-height: 1.6; }
                    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                    .button { display: inline-block; padding: 10px 20px; background-color: #4CAF50; color: white; text-decoration: none; border-radius: 5px; }
                </style>
            </head>
            <body>
                <div class='container'>
                    <h2>Verificación de cuenta</h2>
                    <p>Hola,</p>
                    <p>Gracias por registrarte. Por favor, verifica tu cuenta haciendo clic en el siguiente enlace:</p>
                    <p><a href='$verificationLink' class='button'>Verificar mi cuenta</a></p>
                    <p>O copia y pega esta URL en tu navegador:</p>
                    <p>$verificationLink</p>
                    <p>Este enlace expirará en 24 horas.</p>
                    <p>Saludos,<br>El equipo de " . APP_NAME . "</p>
                </div>
            </body>
            </html>
        ";
        $mail->AltBody = "Hola,\n\nGracias por registrarte. Por favor, verifica tu cuenta haciendo clic en el siguiente enlace:\n$verificationLink\n\nEste enlace expirará en 24 horas.\n\nSaludos,\nEl equipo de " . APP_NAME;

        $mail->send();
        return true;
    } catch (Exception $e) {
        error_log("Error al enviar correo: {$e->getMessage()}");
        // Si PHPMailer falla, intentar con mail() nativo
        $subject = "Verificación de cuenta";
        $verificationLink = SITE_URL . "/register.php?token=" . $token;
        $message = "Hola,\n\nGracias por registrarte. Por favor, verifica tu cuenta haciendo clic en el siguiente enlace:\n$verificationLink\n\nEste enlace expirará en 24 horas.\n\nSaludos,\nEl equipo de " . APP_NAME;
        $headers = "From: no-reply@" . parse_url(SITE_URL, PHP_URL_HOST) . "\r\n";
        return mail($email, $subject, $message, $headers);
    }
}
