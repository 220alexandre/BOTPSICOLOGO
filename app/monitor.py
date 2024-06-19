import psutil
from flask import Flask, jsonify

app = Flask(__name__)

# Função para obter o uso de CPU e memória
def get_system_usage():
    process = psutil.Process()
    cpu_usage = process.cpu_percent(interval=1)
    memory_usage = process.memory_info().rss / (1024 * 1024)  # Em MB
    return cpu_usage, memory_usage

@app.route('/system_usage')
def system_usage():
    cpu_usage, memory_usage = get_system_usage()
    return jsonify(cpu_usage=cpu_usage, memory_usage=memory_usage)

# Certifique-se de que este script não seja executado quando importado
if __name__ == '__main__':
    app.run(debug=True)
