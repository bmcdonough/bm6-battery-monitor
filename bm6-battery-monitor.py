# bm6-battery-monitor - Read data from BM6 BLE battery monitors
# https://github.com/jeffwdh/bm6-battery-monitor
#
# Wouldn't have been able to create this without the following resources:
# https://github.com/KrystianD/bm2-battery-monitor/blob/master/.docs/reverse_engineering.md
# https://doubleagent.net/bm2-reversing-the-ble-protocol-of-the-bm2-battery-monitor/
# https://www.youtube.com/watch?v=lhLff9VACU4

import argparse
import json
import asyncio
import logging
import re
import sys
from logging.handlers import SysLogHandler
from typing import Dict, List, Tuple, Any, Optional
from Crypto.Cipher import AES
from bleak import BleakClient
from bleak import BleakScanner

# Constants
BM6_ENCRYPTION_KEY = bytearray([108, 101, 97, 103, 101, 110, 100, 255, 254, 48, 49, 48, 48, 48, 48, 57])
BM6_COMMAND_VOLTAGE_TEMP = "d1550700000000000000000000000000"
BM6_MESSAGE_PREFIX = "d15507"
GATT_WRITE_CHAR = "FFF3"
GATT_NOTIFY_CHAR = "FFF4"

# MAC address validation pattern
MAC_ADDRESS_PATTERN = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')

# Set up logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

try:
    syslog_handler = SysLogHandler(address='/dev/log', facility='user')
    syslog_handler.setLevel(logging.DEBUG)
    syslog_formatter = logging.Formatter('bm6-battery-monitor[%(process)d]: %(levelname)s - %(message)s')
    syslog_handler.setFormatter(syslog_formatter)
    logger.addHandler(syslog_handler)
except Exception as e:
    # Fallback to stderr if syslog is not available
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setLevel(logging.DEBUG)
    stderr_formatter = logging.Formatter('%(levelname)s: %(message)s')
    stderr_handler.setFormatter(stderr_formatter)
    logger.addHandler(stderr_handler)
    logger.warning(f"Could not connect to syslog, using stderr: {e}")

def is_valid_mac_address(mac: str) -> bool:
    """Validate MAC address format.
    
    Args:
        mac: MAC address string to validate
        
    Returns:
        bool: True if valid MAC address format, False otherwise
    """
    return bool(MAC_ADDRESS_PATTERN.match(mac))

async def scan_bm6(format: str) -> None:
    """Scan for BM6 devices and display results.
    
    Args:
        format: Output format ('ascii' or 'json')
    """
    logger.debug("Starting BM6 device scan with 5 second timeout")
    device_list: List[Tuple[str, int]] = []
    
    try:
        scan = await BleakScanner.discover(return_adv=True, timeout=5)
        logger.debug(f"Scan completed, found {len(scan)} total devices")
    except Exception as e:
        logger.error(f"Failed to scan for devices: {e}")
        raise

    # Filter only BM6 devices
    for device in scan.values():
        if device[0].name == "BM6":
            device_list.append((device[0].address, device[1].rssi))
            logger.debug(f"Found BM6 device: {device[0].address} (RSSI: {device[1].rssi})")

    logger.info(f"Found {len(device_list)} BM6 devices")

    # Output data
    if format == "ascii":
        if device_list:
            print("Address           RSSI")
            for address, rssi in device_list:
                print(f"{address} {rssi}")
        else:
            print("No BM6 devices found.")
    elif format == "json":
        print(json.dumps(device_list))

async def get_bm6_data(address: str, format: str) -> None:
    """Connect to a BM6 device and retrieve voltage, temperature, and SoC data.
    
    Args:
        address: BLE MAC address of the BM6 device
        format: Output format ('ascii' or 'json')
        
    Note:
        Temperature readings are in Celsius and can be negative
    """
    logger.debug(f"Connecting to BM6 device at {address}")
    
    if not is_valid_mac_address(address):
        raise ValueError(f"Invalid MAC address format: {address}")

    bm6_data: Dict[str, Any] = {
        "voltage": None,
        "temperature": None,
        "soc": None
    }

    def decrypt(crypted: bytes) -> str:
        """Decrypt BM6 data using AES encryption.
        
        Args:
            crypted: Encrypted data bytes
            
        Returns:
            str: Decrypted data as hex string
        """
        cipher = AES.new(BM6_ENCRYPTION_KEY, AES.MODE_CBC, 16 * b'\0')
        decrypted = cipher.decrypt(crypted).hex()
        return decrypted

    def encrypt(plaintext: bytes) -> bytes:
        """Encrypt data for BM6 using AES encryption.
        
        Args:
            plaintext: Data to encrypt
            
        Returns:
            bytes: Encrypted data
        """
        cipher = AES.new(BM6_ENCRYPTION_KEY, AES.MODE_CBC, 16 * b'\0')
        encrypted = cipher.encrypt(plaintext)
        return encrypted

    async def notification_handler(sender: int, data: bytearray) -> None:
        """Handle notifications from BM6 device.
        
        Args:
            sender: GATT characteristic handle
            data: Notification data
        """
        try:
            message = decrypt(data)
            logger.debug(f"Received notification: {message}")
            
            if message[0:6] == BM6_MESSAGE_PREFIX:
                bm6_data["voltage"] = int(message[15:18], 16) / 100
                bm6_data["soc"] = int(message[12:14], 16)
                
                if message[6:8] == "01":
                    bm6_data["temperature"] = -int(message[8:10], 16)
                else:
                    bm6_data["temperature"] = int(message[8:10], 16)
                
                logger.debug(f"Parsed data - Voltage: {bm6_data['voltage']}V, Temp: {bm6_data['temperature']}°C, SoC: {bm6_data['soc']}%")
        except Exception as e:
            logger.error(f"Error processing notification: {e}")

    try:
        logger.debug(f"Establishing BLE connection to {address} with 30s timeout")
        async with BleakClient(address, timeout=30) as client:
            logger.debug("BLE connection established")
            
            # Send command to start voltage/temperature notifications
            logger.debug("Sending voltage/temperature command")
            command_data = encrypt(bytearray.fromhex(BM6_COMMAND_VOLTAGE_TEMP))
            await client.write_gatt_char(GATT_WRITE_CHAR, command_data, response=True)
            logger.debug("Command sent successfully")

            # Subscribe to notifications
            logger.debug("Starting notification subscription")
            await client.start_notify(GATT_NOTIFY_CHAR, notification_handler)
            logger.debug("Notification subscription active")

            # Wait for readings - need both voltage AND temperature
            logger.debug("Waiting for voltage and temperature readings...")
            timeout_counter = 0
            max_timeout = 100  # 10 seconds at 0.1s intervals
            
            while (bm6_data["voltage"] is None or bm6_data["temperature"] is None) and timeout_counter < max_timeout:
                await asyncio.sleep(0.1)
                timeout_counter += 1
                if timeout_counter % 10 == 0:  # Log every second
                    logger.debug(f"Still waiting for data... ({timeout_counter/10:.1f}s)")
            
            if timeout_counter >= max_timeout:
                logger.error("Timeout waiting for BM6 data")
                raise TimeoutError("Timeout waiting for BM6 data")
            
            logger.debug("Successfully received all data")

            # Clean up
            logger.debug("Stopping notifications")
            await client.stop_notify(GATT_NOTIFY_CHAR)
            logger.debug("Disconnecting from device")

    except Exception as e:
        logger.error(f"Error communicating with BM6 device: {e}")
        raise

    # Output data
    if format == "ascii":
        print(f"Voltage: {bm6_data['voltage']}v")
        print(f"Temperature: {bm6_data['temperature']}C")
        print(f"SoC: {bm6_data['soc']}%")
    elif format == "json":
        print(json.dumps(bm6_data))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Read data from BM6 BLE battery monitors")
    parser.add_argument("--format", choices=["ascii", "json"], default="ascii", help="Output format")
    req = parser.add_mutually_exclusive_group(required=True)
    req.add_argument("--address", metavar="<address>", help="Address of BM6 to poll data from")
    req.add_argument("--scan", action="store_true", help="Scan for available BM6 devices")
    args = parser.parse_args()
    
    try:
        if args.address:
            logger.info(f"Connecting to BM6 device at {args.address}")
            asyncio.run(get_bm6_data(args.address, args.format))
        elif args.scan:
            logger.info("Scanning for BM6 devices")
            asyncio.run(scan_bm6(args.format))
    except KeyboardInterrupt:
        logger.info("Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Application error: {e}")
        sys.exit(1)
