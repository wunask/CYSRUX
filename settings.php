<?php
session_start();

// Set language based on session or default to English
$lang = isset($_SESSION['lang']) ? $_SESSION['lang'] : 'en';

// Language toggle functionality (optional)
if (isset($_GET['lang']) && in_array($_GET['lang'], ['en', 'ar'])) {
    $lang = $_GET['lang'];
    $_SESSION['lang'] = $lang;
}

// Translation mappings for English and Arabic
$translations = [
    'en' => [
        'title' => 'Modify Password',
        'description' => 'Changing the login password frequently helps prevent unauthorized access.',
        'current_password' => 'Current password',
        'new_password' => 'New password',
        'confirm_password' => 'Confirm password',
        'hint' => 'Must be at least 8 characters. A combination of letters and numbers is more secure.',
        'confirm_button' => 'Confirm',
        'current_password_incorrect' => 'The current password is incorrect.',
        'passwords_do_not_match' => 'New passwords do not match.',
        'password_too_short' => 'Password must be at least 8 characters.',
        'password_changed_successfully' => 'Password changed successfully.'
    ],
    'ar' => [
        'title' => 'تعديل كلمة المرور',
        'description' => 'تغيير كلمة المرور بشكل متكرر يساعد في منع الوصول غير المصرح به.',
        'current_password' => 'كلمة المرور الحالية',
        'new_password' => 'كلمة المرور الجديدة',
        'confirm_password' => 'تأكيد كلمة المرور',
        'hint' => 'يجب أن تكون 8 أحرف على الأقل. مزيج من الحروف والأرقام أكثر أمانًا.',
        'confirm_button' => 'تأكيد',
        'current_password_incorrect' => 'كلمة المرور الحالية غير صحيحة.',
        'passwords_do_not_match' => 'كلمات المرور الجديدة غير متطابقة.',
        'password_too_short' => 'يجب أن تكون كلمة المرور 8 أحرف على الأقل.',
        'password_changed_successfully' => 'تم تغيير كلمة المرور بنجاح.'
    ]
];

// Use the selected language translations
$text = $translations[$lang];

// Define file paths
$file = 'secure/users.txt';
$logFile = 'logs/Login Action Logs.txt'; 
$response = ['status' => '', 'message' => ''];

// Ensure the secure folder and users.txt exist
if (!file_exists('secure')) {
    mkdir('secure', 0777, true);
}
if (!file_exists($file)) {
    file_put_contents($file, "admin:" . password_hash("password123", PASSWORD_DEFAULT) . "\n");
}

// Load stored credentials
$storedCredentials = explode(':', trim(file_get_contents($file)));
$storedUsername = $storedCredentials[0] ?? 'admin';
$storedPasswordHash = $storedCredentials[1] ?? '';

// Function to write log entries
function writeLog($message) {
    global $logFile;
    $timestamp = date('Y-m-d H:i:s');
    $logEntry = "[$timestamp] $message" . PHP_EOL;
    file_put_contents($logFile, $logEntry, FILE_APPEND);
}

// Handle AJAX request within the same file
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['ajax'])) {
    global $text;
    $currentPassword = trim($_POST['current_password']);
    $newPassword = trim($_POST['new_password']);
    $confirmPassword = trim($_POST['confirm_password']);

    // Verify current password
    if (!password_verify($currentPassword, $storedPasswordHash)) {
        $response['status'] = 'error';
        $response['message'] = $text['current_password_incorrect'];
        writeLog("Failed password change attempt: Incorrect current password for user '$storedUsername'.");
    } elseif ($newPassword !== $confirmPassword) {
        $response['status'] = 'error';
        $response['message'] = $text['passwords_do_not_match'];
        writeLog("Failed password change attempt: Passwords do not match.");
    } elseif (strlen($newPassword) < 8) {
        $response['status'] = 'error';
        $response['message'] = $text['password_too_short'];
        writeLog("Failed password change attempt: Password too short.");
    } else {
        // Hash the new password and store it
        $hashedPassword = password_hash($newPassword, PASSWORD_DEFAULT);
        file_put_contents($file, "{$storedUsername}:$hashedPassword\n");

        $response['status'] = 'success';
        $response['message'] = $text['password_changed_successfully'];
        writeLog("Password changed successfully for user '$storedUsername'.");
    }

    // Return JSON response
    echo json_encode($response);
    exit();
}
?>

<!DOCTYPE html>
<html lang="<?php echo $lang; ?>" dir="<?php echo $lang === 'ar' ? 'rtl' : 'ltr'; ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo $text['title']; ?></title>

    <!-- Google Fonts -->
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;500&display=swap" rel="stylesheet">
    <link href="https://fonts.googleapis.com/icon?family=Material+Icons+Outlined" rel="stylesheet">
    <link rel="stylesheet" href="assets/css/settings.css">
</head>
<body>

<div class="password-container">
    <h2><?php echo $text['title']; ?></h2>
    <p><?php echo $text['description']; ?></p>
    
    <form id="passwordForm">
        <!-- Current Password -->
        <div class="input-group">
            <input type="password" id="current_password" name="current_password" placeholder="<?php echo $text['current_password']; ?>" required>
            <span class="material-icons-outlined toggle-password" onclick="togglePasswordVisibility('current_password')">visibility_off</span>
        </div>

        <!-- New Password -->
        <div class="input-group">
            <input type="password" id="new_password" name="new_password" placeholder="<?php echo $text['new_password']; ?>" required>
            <span class="material-icons-outlined toggle-password" onclick="togglePasswordVisibility('new_password')">visibility_off</span>
        </div>
        <p class="hint"><?php echo $text['hint']; ?></p>

        <!-- Confirm Password -->
        <div class="input-group">
            <input type="password" id="confirm_password" name="confirm_password" placeholder="<?php echo $text['confirm_password']; ?>" required>
            <span class="material-icons-outlined toggle-password" onclick="togglePasswordVisibility('confirm_password')">visibility_off</span>
        </div>

        <button type="submit" class="btn confirm-btn" id="confirm-button"><?php echo $text['confirm_button']; ?></button>
    </form>

    <!-- Message Display (Initially Hidden) -->
    <p id="message" class="message" style="display: none;"></p>
</div>

<script>
// Handle form submission with AJAX
document.getElementById('passwordForm').addEventListener('submit', function(event) {
    event.preventDefault(); // Prevent form from reloading the page

    const formData = new FormData(this);
    formData.append('ajax', '1'); // Indicate that this is an AJAX request

    fetch('settings.php', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        const messageElement = document.getElementById('message');
        messageElement.textContent = data.message;

        // Show the message and set its color
        messageElement.style.display = 'block';
        messageElement.style.color = data.status === 'success' ? 'green' : 'red';

        if (data.status === 'success') {
            this.reset(); // Clear the form on success
        }
    })
    .catch(error => console.error('Error:', error));
});



// <!-- JavaScript for Show/Hide Password -->
function togglePasswordVisibility(passwordFieldId) {
    const passwordField = document.getElementById(passwordFieldId);
    const icon = passwordField.nextElementSibling;

    if (passwordField.type === 'password') {
        passwordField.type = 'text';
        icon.textContent = 'visibility';
    } else {
        passwordField.type = 'password';
        icon.textContent = 'visibility_off';
    }
}




</script>

</body>
</html>
