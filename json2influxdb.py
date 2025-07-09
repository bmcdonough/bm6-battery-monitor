import argparse
import json
import sys
import logging
from logging.handlers import SysLogHandler
import re
from datetime import datetime, timezone

# InfluxDB client library
try:
    from influxdb_client import InfluxDBClient, Point, WriteOptions
    from influxdb_client.client.write_api import SYNCHRONOUS
    from influxdb_client.rest import ApiException
except ImportError:
    print("Error: influxdb_client library not found. Please install it using 'pip install influxdb-client'", file=sys.stderr)
    sys.exit(1)

# --- Logging Configuration ---
# Set up a custom logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO) # Set base level to INFO, errors will be ERROR

# Handler for stderr
stderr_handler = logging.StreamHandler(sys.stderr)
stderr_handler.setLevel(logging.INFO) # Set level for stderr output
stderr_formatter = logging.Formatter('%(levelname)s: %(message)s')
stderr_handler.setFormatter(stderr_formatter)
logger.addHandler(stderr_handler)

# Handler for syslog
try:
    # On most Linux systems, /dev/log is the default for syslog.
    # On macOS, it might be /var/run/syslog.
    # On Windows, you might need a different approach or a syslog server.
    syslog_handler = SysLogHandler(address='/dev/log')
    syslog_handler.setLevel(logging.ERROR) # Only send errors to syslog
    syslog_formatter = logging.Formatter('json_to_influxdb: %(levelname)s: %(message)s')
    syslog_handler.setFormatter(syslog_formatter)
    logger.addHandler(syslog_handler)
except Exception as e:
    logger.warning(f"Could not connect to syslog. Errors will only be logged to stderr. Error: {e}")

# --- MAC Address Validation ---
MAC_ADDRESS_PATTERN = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')

def is_mac_address(s):
    """Checks if a string looks like a MAC address."""
    return bool(MAC_ADDRESS_PATTERN.match(s))

# --- Main Script Logic ---
def main():
    parser = argparse.ArgumentParser(
        description="Reads JSON from stdin and writes it to InfluxDB v2.",
        formatter_class=argparse.RawTextHelpFormatter # Preserve newlines in help
    )
    parser.add_argument('--ip', required=True, help='InfluxDB host IP address (e.g., 192.168.1.100)')
    parser.add_argument('--port', type=int, default=8086, help='InfluxDB port (default: 8086)')
    parser.add_argument('--token', required=True, help='InfluxDB API token')
    parser.add_argument('--org', required=True, help='InfluxDB organization name')
    parser.add_argument('--bucket', required=True, help='InfluxDB bucket name')

    args = parser.parse_args()

    # Construct the InfluxDB URL
    influxdb_url = f"http://{args.ip}:{args.port}"
    logger.info(f"Attempting to connect to InfluxDB at: {influxdb_url}")

    client = None
    try:
        # Initialize InfluxDB client
        client = InfluxDBClient(
            url=influxdb_url,
            token=args.token,
            org=args.org,
            timeout=5000 # 5 seconds timeout for connection and operations
        )
        write_api = client.write_api(write_options=SYNCHRONOUS)

        # Verify connection and authorization by attempting a health check
        # This is a good way to catch connection/auth issues early
        try:
            health = client.health()
            if health.status == "pass":
                logger.info(f"Successfully connected to InfluxDB. Version: {health.version}")
            else:
                logger.error(f"InfluxDB is not healthy. Status: {health.status}, Message: {health.message}")
                sys.exit(1)
        except ApiException as e:
            logger.error(f"InfluxDB API error during health check: {e}")
            logger.error(f"Please check --ip, --port, --token, and --org. Exiting.")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Failed to connect to InfluxDB at {influxdb_url}. Error: {e}")
            logger.error(f"Please check --ip and --port. Exiting.")
            sys.exit(1)

        # Read JSON from stdin line by line
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue # Skip empty lines

            try:
                data = json.loads(line)
            except json.JSONDecodeError as e:
                logger.error(f"Malformed JSON input. Skipping this line.")
                logger.error(f"Raw input (printed to stderr): {line}")
                continue # Continue to the next line

            point = Point("json").time(datetime.now(timezone.utc)) # Measurement "json", current UTC time

            if isinstance(data, dict):
                # Handle JSON object: all key-value pairs become fields
                for key, value in data.items():
                    # InfluxDB can handle various types directly, but ensure basic types
                    if isinstance(value, (int, float, bool, str)):
                        point.field(key, value)
                    else:
                        # Log if a field type isn't directly supported or is complex
                        logger.warning(f"Skipping unsupported field type for key '{key}': {type(value)}. Value: {value}")
                
            elif isinstance(data, list) and len(data) == 1 and \
                 isinstance(data[0], list) and len(data[0]) == 2:
                # Handle specific array format: [["MAC_ADDRESS", RSSI_VALUE]]
                value1, value2 = data[0][0], data[0][1]

                # Process first value as MAC address tag
                if isinstance(value1, str) and is_mac_address(value1):
                    point.tag("mac_address", value1)
                else:
                    logger.warning(f"First value in array is not a valid MAC address or type. "
                                   f"Skipping as mac_address tag. Value: '{value1}'")
                    # If not a MAC, we could consider making it a field or skipping this point entirely
                    # For now, if mac_address tag logic fails, we'll still try to write RSSI if present.
                    # Or, you could make this a critical error and 'continue'
                    
                # Process second value as RSSI field
                if isinstance(value2, (int, float)) and value2 < 0:
                    point.field("rssi", value2)
                else:
                    logger.warning(f"Second value in array is not a negative number for RSSI or type. "
                                   f"Skipping as rssi field. Value: '{value2}'")
                    # If RSSI logic fails, we might end up with a point with only a tag or no fields,
                    # InfluxDB generally requires at least one field.

            else:
                logger.warning(f"Unsupported JSON format: {type(data)}. Skipping this input.")
                logger.warning(f"Raw input (printed to stderr): {line}")
                continue # Skip unsupported formats

            # Check if any fields were added to the point, InfluxDB requires at least one field
            if not point._fields:
                logger.warning(f"No valid fields could be extracted from input: {line}. Skipping point.")
                continue

            # Write the point to InfluxDB
            try:
                write_api.write(bucket=args.bucket, record=point)
                # logger.info(f"Successfully wrote data to InfluxDB: {point.to_line_protocol().strip()}")
            except ApiException as e:
                logger.error(f"InfluxDB API error during write operation: {e.status} - {e.reason}")
                logger.error(f"Response Body: {e.body}")
                logger.error(f"Failed to write point: {point.to_line_protocol().strip()}")
            except Exception as e:
                logger.error(f"An unexpected error occurred during InfluxDB write: {e}")
                logger.error(f"Failed to write point: {point.to_line_protocol().strip()}")

    except KeyboardInterrupt:
        logger.info("Script interrupted by user. Exiting.")
    finally:
        if client:
            client.close()
            logger.info("InfluxDB client closed.")

if __name__ == '__main__':
    main()
