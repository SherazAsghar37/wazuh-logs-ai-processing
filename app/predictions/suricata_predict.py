import json
from datetime import datetime
import numpy as np
import pandas as pd

def predict_suricata(log,scaler,clf,le):
  try:
    # log = json.load(log)
    print("log = ", log)
    data = log.get("data", {})
    flow = data.get("flow", {})
    
    # print("data = ", data)
    # print("flow = ", flow)

    fwd_packets = int(flow.get("pkts_toserver", 0))
    bwd_packets = int(flow.get("pkts_toclient", 0))
    fwd_bytes   = int(flow.get("bytes_toserver", 0))
    bwd_bytes   = int(flow.get("bytes_toclient", 0))

    start_time = flow.get("start")
    end_time = data.get("timestamp")

    flow_duration = get_flow_duration(start_time, end_time)
    duration_s = flow_duration / 1000 if flow_duration else 1

    total_bytes = fwd_bytes + bwd_bytes
    total_packets = fwd_packets + bwd_packets

    # print("fwd_packets = ", fwd_packets)
    # print("bwd_packets = ", bwd_packets)
    # print("fwd_bytes = ", fwd_bytes)
    # print("bwd_bytes = ", bwd_bytes)
    # print("flow_duration = ", flow_duration)
    # print("duration_s = ", duration_s)
    # print("total_bytes = ", total_bytes)
    # print("total_packets = ", total_packets)

    record = {
            "Init Bwd Win Bytes": bwd_bytes / bwd_packets if bwd_packets else 0,
            "Flow IAT Std": flow_duration / fwd_packets if fwd_packets else 0,  #
            "Fwd Packet Length Max": fwd_bytes / fwd_packets if fwd_packets else 0,
            "Fwd Packet Length Std": np.std([fwd_bytes / fwd_packets]*fwd_packets) if fwd_packets else 0
        }

    # Convert to DataFrame for scaler
    X_new = pd.DataFrame([record])
    X_new_scaled = scaler.transform(X_new)
    
    
    # print("X_new = ",X_new)
    
    

    # Predict
    pred = clf.predict(X_new_scaled)
    
    # print("pred = ",pred)
    pred_label = le.inverse_transform(pred)
    
    # print("pred_label = ",pred_label)
    print("\nSURICATA FINAL PREDICTION:")
    print(pred_label)

  except Exception as e:
    print(f"Error processing JSON: {e}")
    
    
def get_flow_duration(start, end):
    fmt = "%Y-%m-%dT%H:%M:%S.%f%z"
    try:
        start_dt = datetime.strptime(start, fmt)
        end_dt = datetime.strptime(end, fmt)
        return (end_dt - start_dt).total_seconds() * 1000
    except:
        return None