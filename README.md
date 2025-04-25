# Wazuh Webhook Integration

This repository provides a simple webhook integration for Wazuh to forward security alerts to a custom webhook server using Python and Flask.

## 📌 Overview
The integration allows Wazuh to send alerts in JSON format to a webhook endpoint. The webhook server logs or processes the alerts as needed.

## 🛠️ Configuration Steps

### 1️⃣ Configure Wazuh Manager

Edit the `ossec.conf` file to add a custom integration for the webhook:

```xml
<integration>
    <name>custom-webhookpy</name>
    <hook_url>http://<WEBHOOK_SERVER_IP>:5000/wazuh-webhook</hook_url>
    <level><MIN_ALERT_LEVEL></level>
     <!--           OR 
      <rule_id> </rule_id>
      <group> </group>
    -->
    <alert_format>json</alert_format>
</integration>
```

🔹 Example:

```xml
<integration>
    <name>custom-webhookpy</name>
    <hook_url>http://192.168.2.30:5000/wazuh-webhook</hook_url>
    <level>3</level>
    <alert_format>json</alert_format>
</integration>
```

### 2️⃣ Create the Webhook Integration Script

Navigate to Wazuh's integration directory:

```sh
cd /var/ossec/integrations/
```

Create the script:

```sh
vi custom-webhookpy
```

Paste the following Python script:

```python
#!/usr/bin/env python3
import sys
import json
import requests

if len(sys.argv) < 4:
    print("Usage: custom-webhook.py <alert_file> <api_key> <hook_url>")
    sys.exit(1)

alert_file = sys.argv[1]
api_key = sys.argv[2]
hook_url = sys.argv[3]

try:
    with open(alert_file, 'r') as f:
        alert_data = json.load(f)

    headers = {'Content-Type': 'application/json'}
    response = requests.post(hook_url, json=alert_data, headers=headers)

    print(f"Sent alert to {hook_url}, Response: {response.status_code}, {response.text}")
except Exception as e:
    print(f"Error sending alert: {str(e)}")
    sys.exit(1)
```

Save and exit. Then set the necessary permissions:

```sh
chmod 750 custom-webhookpy
chown root:wazuh custom-webhookpy
```

Install dependencies:

```sh
pip3 install "urllib3<2"
pip3 install requests
```

Monitor logs to verify integration:

```sh
tail -f /var/ossec/logs/ossec.log | grep webhook
```

### 3️⃣ Deploy the Webhook Receiver

On the machine running the webhook server (`192.168.2.30` in our example), install Flask:

```sh
pip install flask
pip install mysql
pip install mysql-connector-python
```

Create the webhook server script:

```sh
vi webhook.py
```

Paste the following Flask application:

```python
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/wazuh-webhook', methods=['POST'])
def wazuh_webhook():
    try:
        alert = request.json
        print("Received alert:", alert)

        with open("alerts.log", "a") as log_file:
            log_file.write(str(alert) + "\n")

        return jsonify({"status": "success", "message": "Alert received"}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
```

Save and exit, then make the script executable:

```sh
chmod +x webhook.py
```

Run the webhook server:

```sh
python webhook.py
OR 
run at the background : nohup python3 webhook.py > webhook.log 2>&1 &
```

## ✅ Testing the Integration
To check if the webhook is receiving alerts, monitor the logs:

```sh
tail -f alerts.log
```

You should see incoming alerts from Wazuh!

---

## 📢 Notes
- Replace `<WEBHOOK_SERVER_IP>` with the actual IP of your webhook server.
- Adjust `<MIN_ALERT_LEVEL>` to set the minimum severity level for alerts.
- Ensure the webhook server allows incoming connections on port `5000`.

## 📖 License
This project is licensed under the MIT License.

---

💡 **Enjoy secure monitoring with Wazuh and Webhooks!** 🚀

