<?php
session_start();

if (isset($_GET['lang'])) {
    $_SESSION['lang'] = $_GET['lang'] === 'ar' ? 'ar' : 'en';
}

// Ensure the user is logged in
if (!isset($_SESSION['username'])) {
    header("Location: login");
    exit;
}

// Set the language based on session or default to English
$lang = isset($_SESSION['lang']) ? $_SESSION['lang'] : 'en';

// Define text translations for English and Arabic
$messages = [
    'en' => [
        'admin_panel' => "Admin Panel",
        'dashboard' => "Dashboard",
        'scan_report' => "Scan Report",
        'log_viewer' => "Log Viewer",
        'cve_search' => "CVE Search",
        'settings' => "Settings",
        'logout' => "Logout",
        'session_expired' => "Session expired. Please log in again."
    ],
    'ar' => [
        'admin_panel' => "لوحة الإدارة",
        'dashboard' => "لوحة التحكم",
        'scan_report' => "التقارير ",
        'log_viewer' => "عارض السجل",
        'cve_search' => "البحث عن الثغرات",
        'settings' => "الإعدادات",
        'logout' => "تسجيل الخروج",
        'session_expired' => "انتهت الجلسة. يرجى تسجيل الدخول مرة أخرى."
    ]
];

// Extract messages for easier use in HTML
$admin_panel_text = $messages[$lang]['admin_panel'];
$dashboard_text = $messages[$lang]['dashboard'];
$scan_report_text = $messages[$lang]['scan_report'];
$log_viewer_text = $messages[$lang]['log_viewer'];
$cve_search_text = $messages[$lang]['cve_search'];
$settings_text = $messages[$lang]['settings'];
$logout_text = $messages[$lang]['logout'];
$session_expired_message = $messages[$lang]['session_expired'];

// Define allowed pages and sanitize input
$allowedPages = ['dashboard', 'scan_report', 'log', 'search_cve', 'settings'];
$page = filter_input(INPUT_GET, 'page', FILTER_SANITIZE_STRING) ?? 'dashboard';
if (!in_array($page, $allowedPages)) {
    $page = 'dashboard'; // Default to dashboard if invalid
}

// Session timeout check
if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity']) > 300) {
    session_unset();
    session_destroy();
    header("Location: login.php?message=" . urlencode($session_expired_message));
    exit();
}
$_SESSION['last_activity'] = time(); // Update last activity time
?>
<!DOCTYPE html>
<html lang="<?php echo $lang; ?>">

<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title><?php echo $admin_panel_text; ?> | CYSRUX</title>

    <!-- Favicon -->
    <link rel="icon" type="image/png" href="assets/img/logo-dark.png">

    <!-- Google Fonts -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&display=swap" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined" rel="stylesheet">

    <!-- Global CSS -->
    <link rel="stylesheet" href="assets/css/style-index.css">

    <?php
    $cssPages = ['dashboard', 'scan_report', 'log', 'search_cve', 'settings'];
    if (in_array($page, $cssPages) && file_exists("assets/css/{$page}.css")) {
        echo "<link rel='stylesheet' href='assets/css/{$page}.css'>";
    }
    ?>

    <!-- jQuery and Theme Switch JS -->
    <script src="https://code.jquery.com/jquery-3.5.1.min.js"></script>
    <script src="index.js"></script>
</head>

<body>

<nav class="menu-bar" dir="<?php echo $lang === 'ar' ? 'rtl' : 'ltr'; ?>">
        <div class="menu-bar-header">
            <img src="assets/img/logo-light.png" alt="Light Logo" class="logo logo-light">
            <img src="assets/img/logo-dark.png" alt="Dark Logo" class="logo logo-dark">
            <h2><?php echo $admin_panel_text; ?></h2>
        </div>

    <!-- Desktop Menu Links -->
    <ul class="menu-links" id="menu-links">
        <li><a href="?page=dashboard" class="<?php echo $page === 'dashboard' ? 'active' : ''; ?>">
            <span class="material-symbols-outlined">dashboard</span><?php echo $dashboard_text; ?></a>
        </li>
        <li><a href="?page=scan_report" class="<?php echo $page === 'scan_report' ? 'active' : ''; ?>">
            <span class="material-symbols-outlined">search</span><?php echo $scan_report_text; ?></a>
        </li>
        <li><a href="?page=log" class="<?php echo $page === 'log' ? 'active' : ''; ?>">
            <span class="material-symbols-outlined">list_alt</span><?php echo $log_viewer_text; ?></a>
        </li>
        <li><a href="?page=search_cve" class="<?php echo $page === 'search_cve' ? 'active' : ''; ?>">
            <span class="material-symbols-outlined">policy</span><?php echo $cve_search_text; ?></a>
        </li>
    </ul>

    <!-- Right Links for Desktop -->
    <ul class="right-links">
    <li class="theme-toggle-desktop">
        <div class="toggle-container">
            <svg id="sun-desktop" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="white" style="cursor: pointer;">
                <circle cx="12" cy="12" r="5"/>
                <line x1="12" y1="1" x2="12" y2="4" stroke="white" stroke-width="2"/>
                <line x1="12" y1="20" x2="12" y2="23" stroke="white" stroke-width="2"/>
                <line x1="4.22" y1="4.22" x2="6.34" y2="6.34" stroke="white" stroke-width="2"/>
                <line x1="17.66" y1="17.66" x2="19.78" y2="19.78" stroke="white" stroke-width="2"/>
                <line x1="1" y1="12" x2="4" y2="12" stroke="white" stroke-width="2"/>
                <line x1="20" y1="12" x2="23" y2="12" stroke="white" stroke-width="2"/>
                <line x1="4.22" y1="19.78" x2="6.34" y2="17.66" stroke="white" stroke-width="2"/>
                <line x1="17.66" y1="6.34" x2="19.78" y2="4.22" stroke="white" stroke-width="2"/>
            </svg>
            <img id="moon-desktop" src="assets/img/moon1.svg" alt="Moon Icon" style="cursor: pointer; display: none;" />
        </div>
    </li>

    <!-- Language Toggle Link -->
    <li>
        <a href="?lang=<?php echo $lang === 'ar' ? 'en' : 'ar'; ?>" class="language-toggle">
            <i class="fas fa-globe"></i>
            <span><?php echo $lang === 'ar' ? 'English' : 'العربية'; ?></span>
        </a>
    </li>


    <li>
        <a href="logout.php" class="logout" onclick="return confirmLogout();">
            <span class="material-symbols-outlined">logout</span>
            <span class="logout-text"><?php echo $logout_text; ?></span>
        </a>
    </li>
<!-- Notification Icon -->
<li>
<a href="#" class="notification-icon" onclick="toggleNotificationPanel(); return false;">
    <span class="material-symbols-outlined">notifications</span>
    <span class="badge"></span>
</a>

<div id="notificationPanel" class="notification-panel" style="display: none;">
    <h3>Notifications</h3>
    <button onclick="markAllAsRead()" class="mark-read-button">Mark All as Read</button>
    <ul id="notificationList">
        <!-- Notifications will be dynamically loaded here -->
    </ul>
</div>


</li>

    <li>
        <a href="?page=settings" class="settings">
            <span class="material-symbols-outlined">settings</span>
        </a>
    </li>
    <li>
        <a href="#" class="shutdown" onclick="confirmShutdown()">
            <span class="material-symbols-outlined">power_settings_new</span>
        </a>
    </li>
    <li>
        <a href="#" class="reboot" onclick="confirmReboot()">
            <span class="material-symbols-outlined">restart_alt</span>
        </a>
    </li>
</ul>

<!-- Hamburger Icon and Theme Toggle for Mobile -->
<div class="theme-toggle-mobile">
    <svg id="sun-mobile" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="white" style="cursor: pointer;">
        <circle cx="12" cy="12" r="5"/>
        <line x1="12" y1="1" x2="12" y2="4" stroke="white" stroke-width="2"/>
        <line x1="12" y1="20" x2="12" y2="23" stroke="white" stroke-width="2"/>
        <line x1="4.22" y1="4.22" x2="6.34" y2="6.34" stroke="white" stroke-width="2"/>
        <line x1="17.66" y1="17.66" x2="19.78" y2="19.78" stroke="white" stroke-width="2"/>
        <line x1="1" y1="12" x2="4" y2="12" stroke="white" stroke-width="2"/>
        <line x1="20" y1="12" x2="23" y2="12" stroke="white" stroke-width="2"/>
        <line x1="4.22" y1="19.78" x2="6.34" y2="17.66" stroke="white" stroke-width="2"/>
        <line x1="17.66" y1="6.34" x2="19.78" y2="4.22" stroke="white" stroke-width="2"/>
    </svg>
    <img id="moon-mobile" src="assets/img/moon1.svg" alt="Moon Icon" style="cursor: pointer; display: none;" />
</div>

</div>
<div class="mobile-header">
    <div class="hamburger-menu" onclick="toggleMobileMenu()">
        <span></span>
        <span></span>
        <span></span>
    </div>

<!-- Mobile-Only Menu -->
<ul class="mobile-menu" id="mobile-menu">
    <li><a href="?page=dashboard" class="<?php echo $page === 'dashboard' ? 'active' : ''; ?>">
        <span class="material-symbols-outlined">dashboard</span><?php echo $dashboard_text; ?></a>
    </li>
    <li><a href="?page=scan_report" class="<?php echo $page === 'scan_report' ? 'active' : ''; ?>">
        <span class="material-symbols-outlined">search</span><?php echo $scan_report_text; ?></a>
    </li>
    <li><a href="?page=log" class="<?php echo $page === 'log' ? 'active' : ''; ?>">
        <span class="material-symbols-outlined">list_alt</span><?php echo $log_viewer_text; ?></a>
    </li>
    <li><a href="?page=search_cve" class="<?php echo $page === 'search_cve' ? 'active' : ''; ?>">
        <span class="material-symbols-outlined">policy</span><?php echo $cve_search_text; ?></a>
    </li>
    <li><a href="?page=settings" class="<?php echo $page === 'settings' ? 'active' : ''; ?>">
        <span class="material-symbols-outlined">settings</span><?php echo $settings_text; ?></a>
    </li>
    <li><a href="logout.php" class="logout" onclick="return confirmLogout();">
        <span class="material-symbols-outlined">logout</span><?php echo $logout_text; ?></a>
    </li>
    <li>
        <a href="?lang=<?php echo $lang === 'ar' ? 'en' : 'ar'; ?>" class="language-toggle">
            <i class="fas fa-globe"></i>
            <span><?php echo $lang === 'ar' ? 'English' : 'العربية'; ?></span>
        </a>
    </li>
</ul>

</nav>

<div class="content-area" id="content-area">
    <?php
    switch ($page) {
        case 'dashboard':
            include 'dashboard.php';
            break;
        case 'scan_report':
            include 'scan_report.php';
            break;
        case 'log':
            include 'log.php';
            break;
        case 'search_cve':
            include 'search_cve.php';
            break;
        case 'settings':
            include 'settings.php';
            break;
        default:
            echo "<p>Page not found.</p>";
            break;
    }
    ?>
</div>

</body>
</html>
