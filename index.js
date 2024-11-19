document.addEventListener('DOMContentLoaded', () => {
    const body = document.body;

    // Theme Toggle Elements (Desktop and Mobile)
    const sunIconDesktop = document.getElementById('sun-desktop');
    const moonIconDesktop = document.getElementById('moon-desktop');
    const sunIconMobile = document.getElementById('sun-mobile');
    const moonIconMobile = document.getElementById('moon-mobile');

    // Logos for Light and Dark Modes
    const lightLogo = document.querySelector('.logo-light');
    const darkLogo = document.querySelector('.logo-dark');

    // Load the saved theme from localStorage or default to 'dark'
    const savedTheme = localStorage.getItem('theme') || 'dark';
    applyTheme(savedTheme);

    // Apply the selected theme (light or dark)
    function applyTheme(theme) {
        const isLightMode = theme === 'light';
        body.classList.toggle('light-mode', isLightMode);

        // Toggle visibility of logos
        lightLogo.style.display = isLightMode ? 'block' : 'none';
        darkLogo.style.display = isLightMode ? 'none' : 'block';

        // Toggle visibility of theme icons
        toggleIcons(isLightMode);
    }

    // Toggle visibility of sun and moon icons based on the theme
    function toggleIcons(isLightMode) {
        sunIconDesktop.style.display = isLightMode ? 'none' : 'inline';
        moonIconDesktop.style.display = isLightMode ? 'inline' : 'none';
        sunIconMobile.style.display = isLightMode ? 'none' : 'inline';
        moonIconMobile.style.display = isLightMode ? 'inline' : 'none';
    }



    
    // Switch theme and save to localStorage
    function switchTheme() {
        const isLightMode = body.classList.contains('light-mode');
        const newTheme = isLightMode ? 'dark' : 'light';
        applyTheme(newTheme);
        localStorage.setItem('theme', newTheme);
    }

    // Add event listeners for theme toggle icons
    [sunIconDesktop, moonIconDesktop, sunIconMobile, moonIconMobile].forEach(icon => {
        icon?.addEventListener('click', switchTheme);
    });

    // Mobile Menu Toggle
    const mobileMenu = document.getElementById('mobile-menu');
    document.querySelector('.hamburger-menu').addEventListener('click', toggleMobileMenu);

    function toggleMobileMenu() {
        mobileMenu.classList.toggle('active');
    }

    // Inactivity Management
    const warningTime = 4 * 60 * 1000; // 4 minutes
    const logoutTime = 5 * 60 * 1000; // 5 minutes
    let warningTimeout, logoutTimeout;

    // Reset inactivity timers
    function resetTimers() {
        clearTimeout(warningTimeout);
        clearTimeout(logoutTimeout);

        warningTimeout = setTimeout(() => {
            alert("You have been inactive for a while. You will be logged out soon if no activity is detected.");
        }, warningTime);

        logoutTimeout = setTimeout(logoutUser, logoutTime);
    }

    // Logout user and redirect to login
    function logoutUser() {
        $.ajax({
            url: 'logout.php',
            method: 'POST',
            success: function () {
                window.location.href = 'login.php?message=You were logged out due to inactivity.';
            },
            error: function () {
                alert('Logout failed. Please try again.');
            }
        });
    }

    // Monitor user activity
    window.onload = resetTimers;
    document.onmousemove = resetTimers;
    document.onkeypress = resetTimers;

    // Reset timers after dynamic content loads
    function loadContent(page) {
        $('#content-area').load(page, resetTimers);
    }
});

// Confirm Logout Action
function confirmLogout() {
    const confirmation = confirm("Are you sure you want to logout?");
    if (confirmation) {
        window.location.href = 'logout.php'; // Redirect to logout page
    }
    return false; // Prevent the default action
}

// Confirm Reboot Action
function confirmReboot() {
    const confirmation = confirm("Are you sure you want to reboot the system?");
    if (confirmation) {
        $.ajax({
            url: 'system.php?action=reboot',
            method: 'POST',
            dataType: 'json', // Expect JSON response from the server
            success: function (response) {
                if (response.message) {
                    alert(response.message); // Display server's message
                } else {
                    alert('Reboot initiated, but no response received.');
                }
            },
            error: function (xhr, status, error) {
                alert('Error: ' + error);
            }
        });
    }
}

// Confirm Shutdown Action
function confirmShutdown() {
    const confirmation = confirm("Are you sure you want to shut down the system?");
    if (confirmation) {
        $.ajax({
            url: 'system.php?action=shutdown',
            method: 'POST',
            dataType: 'json', // Expect JSON response from the server
            success: function (response) {
                if (response.message) {
                    alert(response.message); // Display server's message
                } else {
                    alert('Shutdown initiated, but no response received.');
                }
            },
            error: function (xhr, status, error) {
                alert('Error: ' + error);
            }
        });
    }
}


function toggleNotifications(event) {
    event.preventDefault();
    const panel = document.getElementById('notificationPanel');
    panel.style.display = panel.style.display === 'none' ? 'block' : 'none';

    if (panel.style.display === 'block') {
        loadNotifications(); // Fetch notifications when panel is opened
    }
}

// Function to load notifications
function loadNotifications() {
    fetch('get_notifications.php')
        .then(response => response.json())
        .then(data => {
            const notificationList = document.getElementById('notificationList');
            const badge = document.querySelector('.notification-icon .badge');

            // Clear current notifications
            notificationList.innerHTML = '';

            // Display notifications in the list
            data.notifications.forEach(notification => {
                const li = document.createElement('li');
                li.textContent = notification;
                notificationList.appendChild(li);
            });

            // Update the badge count
            badge.textContent = data.badgeCount > 0 ? data.badgeCount : '';
        })
        .catch(error => console.error('Error fetching notifications:', error));
}

// Function to mark all notifications as read
function markAllAsRead() {
    fetch('get_notifications.php?markRead=1')
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                loadNotifications(); // Reload notifications
                document.querySelector('.notification-icon .badge').textContent = ''; // Clear badge
            }
        })
        .catch(error => console.error('Error marking notifications as read:', error));
}

// Load notifications on page load
document.addEventListener('DOMContentLoaded', () => {
    loadNotifications();
});
function toggleNotificationPanel() {
    const panel = document.getElementById('notificationPanel');
    panel.style.display = panel.style.display === 'none' ? 'block' : 'none';
}
