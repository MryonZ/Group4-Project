from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

# 控制器 REST 接口地址
CONTROLLER_URL = "http://127.0.0.1:8080/permit"  # 如果是本机运行 Ryu，就写 127.0.0.1；否则写控制器的实际 IP

@app.route('/auth_mac', methods=['POST'])  # 注意路径
def authorize():
    mac = request.json.get('mac')
    if not mac:
        return jsonify({"error": "Missing 'mac' parameter."}), 400

    print(f"Received authentication request for MAC: {mac}")

    try:
        res = requests.post(CONTROLLER_URL, json={"mac": mac})
        if res.status_code == 200:
            return "Authentication successful.", 200
        else:
            return f"Controller responded with error: {res.text}", res.status_code
    except Exception as e:
        return f"Authentication failed. Could not connect to controller: {e}", 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
