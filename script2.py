import os
import subprocess
import time
import logging
import netifaces

# Configure logging
output_file = "/var/log/ethernet_check_log.txt"
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s: %(message)s',
    handlers=[
        logging.FileHandler(output_file),
        logging.StreamHandler()  # Outputs to console
    ]
)

# Function to check if the Ethernet interface exists
def interface_exists(interface='wlan0'):
    interface_path = f"/sys/class/net/{interface}/operstate"
    return os.path.exists(interface_path)

# Function to check if Ethernet cable is connected (interface is "up")
def is_ethernet_connected(interface='wlan0'):
    if not interface_exists(interface):
        logging.warning(f"Interface {interface} does not exist.")
        return False
    try:
        result = subprocess.run(["cat", f"/sys/class/net/{interface}/operstate"], capture_output=True, text=True)
        return result.stdout.strip() == "up"
    except Exception as e:
        logging.error(f"Error checking Ethernet status: {e}")
        return False

# Function to check if the interface has an IP address
def has_ip_address(interface='wlan0'):
    try:
        addrs = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in addrs:
            ip_info = addrs[netifaces.AF_INET][0]
            ip_address = ip_info.get('addr')
            if ip_address:
                #logging.info(f"Interface {interface} has IP address: {ip_address}")
                return True
        logging.warning(f"Interface {interface} does not have an IP address.")
        return False
    except Exception as e:
        logging.error(f"Error checking IP address for {interface}: {e}")
        return False

# Function to monitor interface status changes (up/down) before running the next scan
def wait_for_interface_change(interface='wlan0'):
    was_connected = is_ethernet_connected(interface) and has_ip_address(interface)
    
    while True:
        currently_connected = is_ethernet_connected(interface) and has_ip_address(interface)
        if currently_connected != was_connected:
            logging.info(f"Interface {interface} status changed. Current status: {'Connected' if currently_connected else 'Disconnected'}.")
            return  # Break loop when status changes
        time.sleep(10)  # Sleep for 10 seconds and recheck

# Main function to check the interface and run scan60.py if connected and has an IP
def main():
    interface = 'eth0'  # Default interface name, change if necessary

    while True:
        if interface_exists(interface):
            if is_ethernet_connected(interface) and has_ip_address(interface):
                logging.info(f"Ethernet connected and IP assigned. Running scan  on {interface}...")
                
                # Run scan60.py
                subprocess.run(["python3", "/var/www/html/bot.py"])  # Adjust the path to your scan script
                
                logging.info("Scan completed. Waiting for interface status change to run next scan.")
                
                # Wait for the interface status to change (either down or reconnected)
                wait_for_interface_change(interface)
            else:
                logging.warning(f"No connection or no IP address on {interface}. Retrying in 10 seconds...")
                time.sleep(10)  # Sleep for 10 seconds and recheck
        else:
            logging.error(f"Interface {interface} does not exist. Retrying in 10 seconds...")
            time.sleep(10)  # Sleep for 10 seconds and recheck

if __name__ == "__main__":
    main()
