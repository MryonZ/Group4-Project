from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

# User database: username-password only
user_db = {
    "1": {"password": "1"},
    "2": {"password": "2"}
}

# Controller API
CONTROLLER_URL = "http://127.0.0.1:8080/permit"

@app.route('/auth_user', methods=['POST'])
def authorize_user():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    mac = data.get("mac")  #  接收 mac

    if not username or not password or not mac:
        return jsonify({"error": "Missing username, password, or mac"}), 400

    # 检查黑名单
    if mac in blacklist:
        return jsonify({"error": f"MAC {mac} is blacklisted. Authorization denied."}), 403

    user = user_db.get(username)
    if not user or user["password"] != password:
        return jsonify({"error": "Invalid username or password"}), 401

    #  通知 Ryu controller 允许该 MAC
    try:
        res = requests.post(CONTROLLER_URL, json={"mac": mac})
        if res.status_code == 200:
            return jsonify({"message": f"User '{username}' authenticated and MAC {mac} authorized"}), 200
        else:
            return jsonify({"error": f"Authenticated but controller returned: {res.text}"}), res.status_code
    except Exception as e:
        return jsonify({"error": f"Authenticated but failed to notify controller: {e}"}), 500
# 黑名单存储
blacklist = set()

@app.route('/blacklist', methods=['GET'])
def get_blacklist():
    return jsonify(sorted(blacklist))


CONTROLLER_URL_DENY = "http://127.0.0.1:8080/deny"

@app.route('/blacklist', methods=['POST'])
def add_to_blacklist():
    mac = request.json.get("mac")
    if not mac:
        return jsonify({"error": "Missing MAC address"}), 400

    blacklist.add(mac)

    # 通知 Ryu 控制器阻止该 MAC
    try:
        res = requests.post(CONTROLLER_URL_DENY, json={"mac": mac})
        if res.status_code == 200:
            return jsonify({"message": f"MAC {mac} added to blacklist and blocked"}), 200
        else:
            return jsonify({"error": f"Controller error: {res.text}"}), res.status_code
    except Exception as e:
        return jsonify({"error": f"Failed to notify controller: {e}"}), 500

@app.route('/blacklist', methods=['DELETE'])
def remove_from_blacklist():
    mac = request.json.get("mac")
    if not mac:
        return jsonify({"error": "Missing MAC address"}), 400

    if mac in blacklist:
        blacklist.remove(mac)

        # 通知 Ryu 控制器解除封禁
        try:
            res = requests.post("http://127.0.0.1:8080/permit", json={"mac": mac})
            if res.status_code != 200:
                return jsonify({"error": f"MAC removed, but Ryu error: {res.text}"}), 500
        except Exception as e:
            return jsonify({"error": f"MAC removed, but failed to contact Ryu: {e}"}), 500

        return jsonify({"message": f"MAC {mac} removed from blacklist and unblocked"}), 200
    else:
        return jsonify({"message": f"MAC {mac} not found in blacklist"}), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
