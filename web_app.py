from flask import Flask, jsonify, request, abort
from flask_cors import CORS
import pandas as pd
import os
import logging

app = Flask(__name__, static_folder="C:/Users/63002/OneDrive/桌面/frontend", static_url_path='')
CORS(app)
logging.basicConfig(level=logging.INFO)

# path of data_finished_processed folder
BASE_PATH = "C:\\Users\\63002\\OneDrive\\test_data_2\\data_finished_processed"

@app.route('/')
def index():
    return app.send_static_file('index.html')

@app.route('/devices', methods=['GET'])
def get_devices():
    devices = [d for d in os.listdir(BASE_PATH) if os.path.isdir(os.path.join(BASE_PATH, d))]
    return jsonify({"devices": devices})

def load_and_tail(file_path, n):
    try:
        if os.path.isfile(file_path):
            df = pd.read_csv(file_path)
            df.fillna(0, inplace=True)
            return df.tail(n)
        else:
            # logging.warning(f"File not found: {file_path}")
            return None
    except Exception as e:
        logging.error(f"Error reading {file_path}: {e}")
        return None
    

def load_full_csv(file_path):
    try:
        if os.path.isfile(file_path):
            df = pd.read_csv(file_path)
            df.fillna(0, inplace=True)
            return df
        else:
            # logging.warning(f"File not found: {file_path}")
            return None
    except Exception as e:
        logging.error(f"Error reading {file_path}: {e}")
        return None



@app.route('/data', methods=['POST'])
def get_device_data():
    device_name = request.json.get('device_name')

    if not device_name:
        abort(400, "device_name is required.")

    if device_name not in get_devices().json["devices"]:
        abort(400, "Invalid device_name.")

    folder_path = os.path.join(BASE_PATH, device_name)

    response_data = {}

    if device_name == "all_device":
        response_data.update(get_all_device_data(folder_path))

    else:
        response_data.update(get_specific_device_data(folder_path, device_name))
    
    return jsonify(response_data)



def get_all_device_data(folder_path):
    metrics = load_and_tail(os.path.join(folder_path, "all_device_aggregated_metrics_per_min.csv"), 120)
    traffic = load_full_csv(os.path.join(folder_path, "all_device_sorted_traffic_last_n_minutes.csv"))
    
    return {
        "all_device_metrics": metrics.to_dict(orient='list') if metrics is not None else {},
        "all_device_traffic": traffic.to_dict(orient='list') if traffic is not None else {}
    }

def get_specific_device_data(folder_path, device_name):
    metrics = load_and_tail(os.path.join(folder_path, f"metrics_per_min_{device_name}.csv"), 120)
    traffic = load_full_csv(os.path.join(folder_path, f"destination_traffic_{device_name}.csv"))
    throughput = load_and_tail(os.path.join(folder_path, f"throughput_per_second_{device_name}.csv"), 300)
    packetsize = load_full_csv(os.path.join(folder_path, f"packet_sizes_count_{device_name}.csv"))

    return {
        "metrics_per_device": metrics.to_dict(orient='list') if metrics is not None else {},
        "traffic_per_device": traffic.to_dict(orient='list') if traffic is not None else {},
        "throughput_per_device": throughput.to_dict(orient='list') if throughput is not None else {},
        "packet_size_record": packetsize.to_dict(orient='list') if packetsize is not None else {}
    }

if __name__ == "__main__":
    app.run(debug=True)
