<?php
session_start();

// Ensure the user is authenticated
if (!isset($_SESSION['username'])) {
    http_response_code(401);
    echo json_encode(['message' => 'Unauthorized. Please log in.']);
    exit;
}

// Check if the user provided a valid action
$action = filter_input(INPUT_GET, 'action', FILTER_SANITIZE_STRING);

header('Content-Type: application/json'); // Set the content type to JSON

if ($action === 'shutdown') {
    // Execute the shutdown command (requires proper permissions)
    $output = shell_exec('sudo shutdown -h now 2>&1');
    echo json_encode(['message' => 'System is shutting down...']);
} elseif ($action === 'reboot') {
    // Execute the reboot command (requires proper permissions)
    $output = shell_exec('sudo reboot 2>&1');
    echo json_encode(['message' => 'System is rebooting...']);
} else {
    http_response_code(400);
    echo json_encode(['message' => 'Invalid action specified.']);
}
?>
