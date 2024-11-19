<?php
session_start();

// Generate a CSRF token if it does not exist
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Language setting based on URL parameter (default to English)
$lang = isset($_GET['lang']) && $_GET['lang'] === 'ar' ? 'ar' : 'en';

// Set messages in both languages
$messages = [
    'en' => [
        'session_expired' => "Session expired. Please log in again.",
        'username_password_required' => "Username and password are required.",
        'user_file_not_found' => "User file not found.",
        'invalid_credentials' => "Invalid username or password.",
        'welcome' => "Welcome to",
        'platform_description' => "Our platform offers top-notch cybersecurity assessments to safeguard your digital assets. Log in to access your security insights and stay protected.",
        'login' => "Login",
        'user_login' => "User Login",
        'username' => "Username",
        'password' => "Password",
        'usernameplace' => "Enter your Username",
        'passwordplace' => "Enter your Password",
        'remember_me' => "Remember Me",
        'all_rights_reserved' => "All rights reserved.",
        'forgot_password' => "Forgot Password?",
        'reset_confirmation' => "Are you sure you want to reset your password? This action will reset the device to default settings and cannot be undone.",
        'reset_successful' => "Device reset successful. Please log in with default credentials.",
    ],
    'ar' => [
        'session_expired' => "انتهت الجلسة. يرجى تسجيل الدخول مرة أخرى.",
        'username_password_required' => "اسم المستخدم وكلمة المرور مطلوبان.",
        'user_file_not_found' => "لم يتم العثور على ملف المستخدم.",
        'invalid_credentials' => "اسم المستخدم أو كلمة المرور غير صحيح.",
        'welcome' => "مرحبًا بكم في",
        'platform_description' => "تقدم منصتنا تقييمات متقدمة للأمن السيبراني لحماية أصولك الرقمية. قم بتسجيل الدخول للوصول إلى معلومات الأمان الخاصة بك والحفاظ على الحماية.",
        'login' => "تسجيل الدخول",
        'user_login' => "تسجيل دخول المستخدم",
        'username' => "اسم المستخدم",
        'password' => "كلمة المرور",
        'usernameplace' => "ادخل اسم المستخدم",
        'passwordplace' => "ادخل كلمة المرور",
        'remember_me' => "تذكرني",
        'all_rights_reserved' => "جميع الحقوق محفوظة.",
        'forgot_password' => "نسيت كلمة المرور؟",
        'reset_confirmation' => "هل أنت متأكد من رغبتك في إعادة تعيين كلمة المرور الخاصة بك؟ سيؤدي ذلك إلى إعادة ضبط الجهاز على الإعدادات الافتراضية ولا يمكن التراجع عنه.",
        'reset_successful' => "تمت إعادة تعيين ضبط الجهاز بنجاح. يرجى تسجيل الدخول باستخدام بيانات الاعتماد الافتراضية.",
    ]
];

// Define file paths and default credentials
$logFile = 'logs/Login Action Logs.txt';
$userFile = 'secure/users.txt';
$scanDir = '/var/www/html/test';
$logsDir = '/var/www/html/logs';
$defaultUsername = "AAdmin";
$defaultPassword = "AAdmin";
$errors = [];
$message = "";

// Enable error reporting
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Create log file if it doesn't exist
if (!file_exists($logFile)) {
    file_put_contents($logFile, "Log File Created: " . date('Y-m-d H:i:s') . PHP_EOL, FILE_APPEND);
}

// Function to write to the log file
function writeLog($message) {
    global $logFile;
    $timestamp = date('Y-m-d H:i:s');
    // Check if the IPv4 address is available, otherwise fall back to IPv6
    $ipAddress = $_SERVER['REMOTE_ADDR'];
    if (filter_var($ipAddress, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        $logEntry = "[$timestamp] [IPv4: $ipAddress] $message" . PHP_EOL;
    } else {
        $logEntry = "[$timestamp] [IPv6: $ipAddress] $message" . PHP_EOL;
    }
    file_put_contents($logFile, $logEntry, FILE_APPEND);
}


/**
 * Recursively delete all files and subdirectories in a specified directory.
 * Logs the deletion process for each file and directory.
 *
 * @param string $dir The directory to delete contents from.
 * @return void
 */
function deleteAll($dir) {
    global $errors;

    if (!is_dir($dir)) {
        $errors[] = "Provided path is not a directory or is inaccessible: $dir";
        writeLog("ERROR: $dir is not a valid directory or inaccessible.");
        return;
    }

    $items = scandir($dir);
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') continue;

        $path = $dir . DIRECTORY_SEPARATOR . $item;

        if (is_dir($path)) {
            deleteAll($path);
            if (!rmdir($path)) {
                $errors[] = "Failed to remove directory: $path. Check permissions.";
                writeLog("ERROR: Failed to remove directory: $path. Check permissions.");
            } else {
                writeLog("Deleted directory: $path");
            }
        } elseif (is_file($path)) {
            if (!is_writable($path)) {
                $errors[] = "Cannot delete file: $path. File is not writable.";
                writeLog("ERROR: Cannot delete file: $path. File is not writable.");
            } elseif (!unlink($path)) {
                $errors[] = "Failed to delete file: $path. Check permissions.";
                writeLog("ERROR: Failed to delete file: $path. Check permissions.");
            } else {
                writeLog("Deleted file: $path");
            }
        } else {
            $errors[] = "Unknown type, skipping: $path";
            writeLog("ERROR: Unknown type, skipping: $path");
        }
    }
}

// Handle POST requests for login or reset
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        die("Invalid CSRF token.");
    }

    if (isset($_POST['login'])) {
        // Login processing
        $username = htmlspecialchars(trim($_POST['username']), ENT_QUOTES, 'UTF-8');
        $password = trim($_POST['password']);
        writeLog("Login attempt for user: $username");

        if (empty($username) || empty($password)) {
            $message = $messages[$lang]['username_password_required'];
            writeLog("Failed login attempt for user: $username - Username or password missing.");
        } else {
            $users = [];
            if (file_exists($userFile)) {
                $lines = file($userFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
                foreach ($lines as $line) {
                    list($file_user, $file_hashed_password) = explode(':', $line);
                    $users[$file_user] = $file_hashed_password;
                }
            } else {
                $message = $messages[$lang]['user_file_not_found'];
                writeLog("ERROR: User file not found.");
            }
            if (array_key_exists($username, $users) && password_verify($password, $users[$username])) {
                session_regenerate_id(true);
                $_SESSION['username'] = $username;
                $_SESSION['lang'] = $lang;
                $_SESSION['last_activity'] = time();
                writeLog("Successful login for user: $username");
                header('Location: index.php');
                exit();
            } else {
                $message = $messages[$lang]['invalid_credentials'];
                writeLog("Failed login attempt for user: $username - Invalid credentials.");
            }
        }
    } elseif (isset($_POST['confirm_reset']) && $_POST['confirm_reset'] === 'yes') {
        // Password reset handling
        writeLog("Password reset initiated by user: {$_SESSION['username']}");
        deleteAll($scanDir);
        deleteAll($logsDir);

        if (file_exists($userFile)) {
            $hashedPassword = password_hash($defaultPassword, PASSWORD_DEFAULT);
            file_put_contents($userFile, "$defaultUsername:$hashedPassword\n");
            writeLog("Password reset successful. Default credentials set for user: $defaultUsername");
            header("Location: login.php?reset_success=1&lang=$lang");
            exit();
        } else {
            $errors[] = $messages[$lang]['user_file_not_found'];
            writeLog("ERROR: User file not found during password reset.");
        }
    }
}

// Initialize CSRF token if not set
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Check for session timeout
$timeoutDuration = 300;
if (isset($_SESSION['username'])) {
    if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity']) > $timeoutDuration) {
        session_unset();
        session_destroy();
        writeLog("Session expired for user: {$_SESSION['username']}");
        header("Location: login.php?lang=$lang&message=" . urlencode($messages[$lang]['session_expired']));
        exit();
    }
    $_SESSION['last_activity'] = time();
}
?>



<!DOCTYPE html>
<html lang="<?php echo $lang; ?>" dir="<?php echo $lang === 'ar' ? 'rtl' : 'ltr'; ?>">
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title><?php echo $messages[$lang]['user_login']; ?> | Admin Panel</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="/assets/css/login.css">
</head>
<body>
<div class="safe-area-wrapper">
    <a href="?lang=<?php echo $lang === 'ar' ? 'en' : 'ar'; ?>" class="language-toggle">
        <i class="fas fa-globe"></i>
        <span><?php echo $lang === 'ar' ? 'English' : 'العربية'; ?></span>
    </a>

    <div class="login-container">
        <div id="welcomeSection" class="left-section">
            <h2><?php echo $messages[$lang]['welcome']; ?></h2>
            <img src="assets/img/logo-dark.png" alt="Cysrux Logo" class="logo-image">
            <h2>Cysrux</h2>
            <p><?php echo $messages[$lang]['platform_description']; ?></p>
            <button class="get-started-button" onclick="showLoginForm()">Get Started</button>
            <!-- Social Media Icons for Mobile Only -->
            <div class="social-wrapper-mobile">
                <a href="https://wa.me/1234567890" class="social-button telegram">
                    <i class="fa-brands fa-telegram"></i>
                </a>
                <a href="https://twitter.com" class="social-button twitter">
                    <i class="fab fa-x-twitter"></i>
                </a>
                <a href="https://cysrux.com" class="social-button website">
                    <i class="fas fa-globe"></i>
                </a>
            </div>
        </div>
        

        <div class="right-section">
            <!-- Login Form -->
            <div id="loginForm">
                <h2><?php echo $messages[$lang]['user_login']; ?></h2>
                <?php if (!empty($message)): ?>
                    <div class="error-message" role="alert">
                        <?php echo htmlspecialchars($message, ENT_QUOTES, 'UTF-8'); ?>
                    </div>
                <?php endif; ?>
                <form method="POST">
                    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                    <div class="form-group input-icon">
                        <i class="fas fa-user"></i>
                        <input type="text" name="username" class="form-control" placeholder="<?php echo $messages[$lang]['usernameplace']; ?>" required>
                    </div>
                    <div class="form-group input-icon">
                        <i class="fas fa-lock"></i>
                        <input type="password" name="password" class="form-control" placeholder="<?php echo $messages[$lang]['passwordplace']; ?>" required>
                    </div>
                    <div class="form-group remember-forgot-container">
                        <span class="remember-me-container">
                            <input type="checkbox" name="remember_me" id="remember_me">
                            <label for="remember_me"><?php echo $messages[$lang]['remember_me']; ?></label>
                        </span>
                        <span class="forgot-password">
                            <a href="javascript:void(0);" onclick="toggleResetForm();"><?php echo $messages[$lang]['forgot_password']; ?></a>
                        </span>
                    </div>
                    <button type="submit" name="login" class="login-button"><?php echo $messages[$lang]['login']; ?></button>
                </form>
            </div>

            <!-- Reset Form (Hidden Initially) -->
            <div id="resetForm" style="display: none;">
                <h3><?php echo $messages[$lang]['reset_confirmation']; ?></h3>
                <form method="POST">
                    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                    <input type="hidden" name="confirm_reset" value="yes">
                    <button type="submit" class="confirm-button">Confirm</button>
                    <button type="button" class="cancel-button" onclick="toggleResetForm()">Cancel</button>
                </form>
            </div>
        </div>
    </div>
</div>

<div class="footer">
    <div class="social-wrapper">
        <a href="https://wa.me/1234567890" class="social-button telegram">
            <i class="fa-brands fa-telegram"></i>
        </a>
        <a href="https://twitter.com" class="social-button twitter">
            <i class="fab fa-x-twitter"></i>
        </a>
        <a href="https://cysrux.com" class="social-button website">
            <i class="fas fa-globe"></i>
        </a>
    </div>
    <small class="footer-center-text">&copy; <?php echo date("Y"); ?> Cysrux. <?php echo $messages[$lang]['all_rights_reserved']; ?></small>
</div>

<script>
// Toggle between login and reset forms
function toggleResetForm() {
    const loginForm = document.getElementById("loginForm");
    const resetForm = document.getElementById("resetForm");

    if (loginForm.style.display === "none") {
        loginForm.style.display = "block";
        resetForm.style.display = "none";
    } else {
        loginForm.style.display = "none";
        resetForm.style.display = "block";
    }
}

function showLoginForm() {
    document.querySelector('.login-container').classList.add('show-login');
}

window.addEventListener('DOMContentLoaded', () => {
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.has('reset_success') && urlParams.get('reset_success') === '1') {
        alert('<?php echo $messages[$lang]['reset_successful']; ?>');
    }
});
</script>
</body>
</html>
