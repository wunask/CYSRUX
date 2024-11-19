<?php
session_start();
$scanDir = '/var/www/html/scan';

// Check for a 'markRead' parameter to clear notifications
if (isset($_GET['markRead']) && $_GET['markRead'] === '1') {
    // Clear notifications by emptying the session variable
    $_SESSION['notifications'] = [];
    echo json_encode(['success' => true]);
    exit;
}

// Initialize the notifications array in session if not already set
if (!isset($_SESSION['notifications'])) {
    $_SESSION['notifications'] = [];
}

// Array to store new notifications
$newNotifications = [];

// Scan the directory for folders to check for new notifications
if (is_dir($scanDir)) {
    $items = scandir($scanDir);
    foreach ($items as $item) {
        if ($item !== '.' && $item !== '..') {
            $path = $scanDir . DIRECTORY_SEPARATOR . $item;
            if (is_dir($path)) {
                // If this folder is new, add it to notifications
                if (!in_array($item, $_SESSION['notifications'])) {
                    $newNotifications[] = "New folder created: " . htmlspecialchars($item);
                    $_SESSION['notifications'][] = $item; // Mark as seen
                }
            }
        }
    }
}

// Return the new notifications in JSON format
header('Content-Type: application/json');
echo json_encode(['notifications' => $newNotifications, 'badgeCount' => count($newNotifications)]);
?>
