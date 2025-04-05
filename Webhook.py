from flask import Flask, request, jsonify
import mysql.connector
import json
import traceback
from datetime import datetime
from mysql.connector.pooling import MySQLConnectionPool

app = Flask(__name__)

# --- Updated Database Configuration ---
DB_CONFIG = {
    "host": "192.168.2.60",
    "user": "manager",
    "password": "P@$$w0rd", # Be cautious storing passwords directly in code for production
    "database": "test2",
    "port": 3306,
    "autocommit": False # Explicitly manage transactions
}

# Create a connection pool
try:
    pool = MySQLConnectionPool(pool_name="mypool", pool_size=10, **DB_CONFIG)
    print("Database connection pool created successfully.")
except mysql.connector.Error as err:
    print(f"Error creating connection pool: {err}")
    # Exit or handle appropriately if the pool can't be created
    exit(1)


def get_severity(level):
    """Maps Wazuh level to severity string."""
    if not isinstance(level, (int, float)):
        return "low" # Default if level is not a number
    if 0 <= level <= 6:
        return "low"
    elif 7 <= level <= 12:
        return "medium"
    # --- Updated severity mapping to match varchar(8) ---
    elif 13 <= level <= 16:
        return "critical"
    return "low" # Default for levels outside defined ranges

def parse_timestamp(timestamp_str):
    """Parses Wazuh timestamp string into datetime object."""
    if not timestamp_str:
        print("Warning: Received empty timestamp string. Using current time.")
        return datetime.now() # Fallback

    # Handle timezone offset like +0000 by removing it
    if '+' in timestamp_str and len(timestamp_str.split('+')[-1]) == 4:
         timestamp_str = timestamp_str.rsplit('+', 1)[0]
    elif '-' in timestamp_str[-5:] and len(timestamp_str.split('-')[-1]) == 4: # Handle negative offsets like -0500
         timestamp_str = timestamp_str.rsplit('-', 1)[0]

    # Remove trailing 'Z' if present (indicates UTC)
    if timestamp_str.endswith('Z'):
        timestamp_str = timestamp_str[:-1]

    # Try parsing with microseconds, fallback to seconds
    try:
        # Handle potential timezone info remnants if any (like a dangling T) - robust parsing
        return datetime.strptime(timestamp_str.split('.')[0], "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        try:
            # Try parsing standard ISO format without microseconds
             return datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S")
        except ValueError as e:
            print(f"Warning: Could not parse timestamp '{timestamp_str}' after attempts. Error: {e}. Using current time.")
            return datetime.now() # Fallback if parsing fails


@app.route('/wazuh-webhook', methods=['POST'])
def wazuh_webhook():
    conn = None # Initialize connection variable outside try
    cursor = None # Initialize cursor variable outside try
    try:
        alert_payload = request.json
        print("Payload received")
        print(alert_payload)

        # Optional: Log the raw payload (consider size and security)
        # try:
        #     with open("alerts.log", "a") as log_file:
        #         log_file.write(json.dumps(alert_payload) + "\n")
        #     print("Saved raw payload to file")
        # except Exception as log_err:
        #      print(f"Warning: Failed to write to log file: {log_err}")

        conn = pool.get_connection()
        cursor = conn.cursor()

        # --- Check if it's an Active Response confirmation ---
        # This check might need refinement based on actual response payload structure
        # Example check: look for a specific field or integration type
        if 'active-responses.log' in str(alert_payload): # More specific check
            print("Processing Active Response payload...")

            # Extract info ABOUT the original alert FROM the response payload
            # Structure may vary based on Wazuh version/config
            original_alert_data = alert_payload.get('data', {}).get('parameters', {}).get('alert', {})
            original_timestamp_str = original_alert_data.get('timestamp')
            print(f"time stamp str {original_timestamp_str}")
            if not original_timestamp_str:
                print("Error: Could not find original alert timestamp in response payload.")
                # Don't commit, resources will be closed in finally
                return jsonify({"status": "error", "message": "Invalid response format: missing original timestamp"}), 400

            original_timestamp_dt = parse_timestamp(original_timestamp_str)
            print(f"time stamp dt {original_timestamp_dt}")
            # Store the full response payload and update status
            # WARNING: Updating based SOLELY on timestamp might affect multiple alerts
            # if timestamps are not unique down to the microsecond level supported by DB.
            # A better approach involves linking via a unique alert ID if available in response.
            update_sql = """
                UPDATE alert
                SET status = %s, full_response = %s, responder = %s , response_desc = %s
                WHERE time = %s
            """
            # Store the entire response payload as a JSON string
            full_response_json = json.dumps(alert_payload)
            values = ("resolved", full_response_json, "Auto-response by wazuh",alert_payload["rule"]["description"],original_timestamp_dt) # Use datetime object directly

            cursor.execute(update_sql, values)
            conn.commit() # Commit the transaction

            if cursor.rowcount > 0:
                print(f"Updated status and full_response for alert(s) with time: {original_timestamp_dt}")
            else:
                 print(f"Warning: No alert found matching time {original_timestamp_dt} to update response.")

            # No need for explicit close here, finally block will handle it
            return jsonify({"status": "success", "message": "Response processed"}), 200

        # --- Process a regular Alert ---
        else:
            print("Processing standard alert payload...")

            timestamp_str = alert_payload.get('timestamp')
            timestamp_dt = parse_timestamp(timestamp_str) # Use the parsed datetime object

            agent_info = alert_payload.get('agent', {})
            computer = agent_info.get('name', 'Unknown Agent')

            rule_info = alert_payload.get('rule', {})
            level = rule_info.get('level', 0)
            severity = get_severity(level) # Use the correct function name
            description = rule_info.get('description', 'No description')

            # Extract account name (adjust path if needed for different alert types)
            # Use .get() chaining for safety against missing keys
            account_name = alert_payload.get('data', {}).get('win', {}).get('eventdata', {}).get('targetUserName') # Will be None if not present

            # Extract source IP/Port (adjust path if needed)
            event_data = alert_payload.get('data', {}).get('win', {}).get('eventdata', {})
            src_ip = event_data.get('SourceIp') # Defaults to None if not found
            src_port = event_data.get('SourcePort') # Defaults to None if not found

            # Construct source string carefully, handling None values
            if "suricata" in alert_payload :
                source_combined = alert_payload["_source"]["data"]["dest_ip"]
            elif alert_payload["agent"]["name"] == "ubuntu-apatch2":
                source_combined = alert_payload["data"]["srcip"]
            else:
                source_combined = f'Local in {alert_payload["agent"]["name"]}' # Or set to None if column allows NULL

            # Set initial status and full alert JSON
            status = "pending"
            full_alert_json = json.dumps(alert_payload)

            print("Extracted alert fields")

            # --- Updated INSERT statement for the 'alert' table ---
            sql = """
                INSERT INTO alert
                (time, source, severity, computer, account_name, description, status, full_alert, full_response)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            # Note: alert_id is auto-increment, full_response is NULL initially
            values = (
                timestamp_dt,         # time (datetime object)
                source_combined[:50], # source (varchar(50)) - Truncate if needed
                severity,             # severity (varchar(8))
                computer[:255],       # computer (varchar(255)) - Truncate if needed
                account_name[:255] if account_name else None, # account_name (varchar(255), nullable) - Truncate
                description,          # description (longtext)
                status,               # status (varchar(25))
                full_alert_json,      # full_alert (longtext)
                None                  # full_response (longtext, NULL initially)
            )

            cursor.execute(sql, values)
            conn.commit() # Commit the transaction
            alert_id = cursor.lastrowid # Get the ID of the inserted row

            print(f"Alert stored successfully with ID: {alert_id}")

            # No need for explicit close here, finally block will handle it
            return jsonify({"status": "success", "message": "Alert stored successfully", "alert_id": alert_id}), 201 # 201 Created

    except mysql.connector.Error as e:
        print(f"MySQL Error: {e.errno} - {e.msg}") # More specific error details
        traceback.print_exc()
        if conn and conn.is_connected(): # Check connection before rollback
             try:
                 conn.rollback() # Rollback transaction on error
                 print("Transaction rolled back.")
             except Exception as rb_err:
                 print(f"Error during rollback: {rb_err}")
        return jsonify({"status": "error", "message": f"Database error: {e.msg}"}), 500
    except json.JSONDecodeError as e:
         print(f"JSON Decode Error: {e}")
         traceback.print_exc()
         # No DB operation likely started, no rollback needed
         return jsonify({"status": "error", "message": f"Invalid JSON received: {e}"}), 400
    except Exception as e:
        print(f"App error: {e}")
        traceback.print_exc()
        if conn and conn.is_connected(): # Check connection before rollback
             try:
                 conn.rollback() # Rollback transaction on general error if conn exists
                 print("Transaction rolled back due to application error.")
             except Exception as rb_err:
                 print(f"Error during rollback: {rb_err}")
        return jsonify({"status": "error", "message": f"An unexpected error occurred: {e}"}), 500
    finally:
        # --- Corrected Finally Block ---
        # Ensure cursor and connection are closed (returned to pool) if they were opened.
        if cursor is not None:
            try:
                cursor.close()
                # print("Cursor closed.") # Optional debug print
            except Exception as cur_err:
                print(f"Warning: Error closing cursor in finally: {cur_err}")
        if conn is not None:
            try:
                conn.close() # Returns the connection to the pool
                print("Database connection returned to pool.")
            except mysql.connector.Error as db_err:
                print(f"Error closing database connection in finally block: {db_err}")
            except Exception as e:
                 print(f"Unexpected error closing connection in finally block: {e}")


if __name__ == '__main__':
    # Make sure host='0.0.0.0' is intended (listens on all interfaces)
    # Remove debug=True for production environments
    app.run(host='0.0.0.0', port=5000, debug=True)
