<?php
// config.php - Configuración de la base de datos y JWT

// Buscar el archivo .env en varias ubicaciones posibles
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
        // Ignorar comentarios
        if (strpos(trim($line), '#') === 0) {
            continue;
        }

        // Verificar que la línea tiene formato correcto
        if (strpos($line, '=') !== false) {
            list($name, $value) = explode('=', $line, 2);
            $name = trim($name);
            $value = trim($value);

            // Quitar comillas si existen
            if (strpos($value, '"') === 0 && substr($value, -1) === '"') {
                $value = substr($value, 1, -1);
            }

            // Definir constante
            if (!defined($name)) {
                define($name, $value);
            }
        }
    }
}

// Solo aquí, después de cargar las variables, puedes imprimir sus valores
echo "DB_HOST: " . DB_HOST . "<br>";
echo "SITE_URL: " . SITE_URL . "<br>";
echo "MAIL_HOST: " . MAIL_HOST . "<br>";
echo "JWT_SECRET: " . JWT_SECRET . "<br>";

// Verificar que las constantes necesarias estén definidas
$requiredConstants = [
    'DB_HOST',
    'SITE_URL',
    'MAIL_HOST',
    'JWT_SECRET', /* otras constantes */
];

foreach ($requiredConstants as $constant) {
    if (!defined($constant)) {
        die("Error: La constante '$constant' no está definida en el archivo .env");
    }
}
// Después de cargar y verificar, imprimir para depuración
echo "DB_HOST: " . DB_HOST . "<br>";
echo "SITE_URL: " . SITE_URL . "<br>";

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
    if (count($parts) != 3) {
        return false;
    }

    list($header, $payload, $signature) = $parts;

    $verifySignature = base64_encode(hash_hmac('sha256', "$header.$payload", JWT_SECRET, true));

    if ($signature !== $verifySignature) {
        return false;
    }

    $payload = json_decode(base64_decode($payload), true);

    if ($payload['exp'] < time()) {
        return false;
    }

    return $payload;
}

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

    // Si no se encuentra el autoloader, usar función mail() nativa
    if (!$autoloaderFound || !class_exists('PHPMailer\PHPMailer\PHPMailer')) {
        // Método alternativo usando mail() nativo
        $subject = "Verificación de cuenta";
        $verificationLink = SITE_URL . "/register.php?token=" . $token;

        $message = "Hola,\n\n";
        $message .= "Gracias por registrarte. Por favor, verifica tu cuenta haciendo clic en el siguiente enlace:\n";
        $message .= $verificationLink . "\n\n";
        $message .= "Este enlace expirará en 24 horas.\n\n";
        $message .= "Saludos,\nEl equipo de " . APP_NAME;

        $headers = "From: " . MAIL_FROM . "\r\n";

        return mail($email, $subject, $message, $headers);
    }

    // Usar PHPMailer
    try {
        $mail = new PHPMailer\PHPMailer\PHPMailer(true);

        // Configuración del servidor con los valores del archivo de configuración
        $mail->isSMTP();
        $mail->Host       = MAIL_HOST;
        $mail->SMTPAuth   = true;
        $mail->Username   = MAIL_USERNAME;
        $mail->Password   = MAIL_PASSWORD;

        if (MAIL_ENCRYPTION === 'ssl') {
            $mail->SMTPSecure = PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_SMTPS;
        } else {
            $mail->SMTPSecure = PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS;
        }

        $mail->Port       = MAIL_PORT;

        // Debug (comenta esta línea en producción)
        // $mail->SMTPDebug = PHPMailer\PHPMailer\SMTP::DEBUG_SERVER;

        // Remitentes y destinatarios
        $mail->setFrom(MAIL_FROM, APP_NAME);
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
        return false;
    }
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
    if (!empty($headers)) {
        if (preg_match('/Bearer\s(\S+)/', $headers, $matches)) {
            $token = $matches[1];
        }
    }

    if (!$token) {
        header('Content-Type: application/json');
        http_response_code(401);
        echo json_encode(['error' => 'Token de autenticación no proporcionado']);
        exit;
    }

    // Verificar token
    $payload = verifyJWT($token);

    if (!$payload) {
        header('Content-Type: application/json');
        http_response_code(401);
        echo json_encode(['error' => 'Token inválido o expirado']);
        exit;
    }

    // Verificar si el token está activo en la base de datos
    $conn = getDbConnection();
    $stmt = $conn->prepare("
        SELECT t.id, ua.activo 
        FROM tokens t 
        JOIN usuario_activo ua ON t.id = ua.id 
        WHERE t.usuario_id = ? AND ua.activo = 1 AND t.fecha_creacion > DATE_SUB(NOW(), INTERVAL t.duracion HOUR)
    ");

    $stmt->bind_param("i", $payload['user_id']);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows === 0) {
        $stmt->close();
        $conn->close();

        header('Content-Type: application/json');
        http_response_code(401);
        echo json_encode(['error' => 'Sesión inválida o expirada']);
        exit;
    }

    $stmt->close();
    $conn->close();

    return $payload['user_id'];
}
