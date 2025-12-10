import re
import pandas as pd
import numpy as np
import joblib

from app.models import snort_scaler as scaler
from app.models import snort_model as model


def preprocess_snort_json(json_data):

    # If single JSON object
    if isinstance(json_data, dict):
        file = pd.DataFrame([json_data])
    else:
        file = pd.DataFrame(json_data)

    # ----------------------------------------
    # Extract PRIORITY
    # ----------------------------------------
    file["Priority"] = file["full_log"].str.extract(r"\[Priority:\s*(\d+)\]").astype(float)

    # ----------------------------------------
    # Extract PROTOCOL
    # ----------------------------------------
    file["Protocol"] = file["full_log"].str.extract(r"\{([A-Z]+)\}")
    proto_map = {"ICMP":1, "PIM":2, "TCP":3, "UDP":4}
    file["Protocol"] = file["Protocol"].map(proto_map).fillna(0).astype(int)

    # ----------------------------------------
    # Extract Source IP and Port
    # ----------------------------------------
    src = file["full_log"].str.extract(r"(\d+\.\d+\.\d+\.\d+):(\d+)")
    file["Source IP"] = src[0]
    file["Source port"] = src[1].astype(float)

    # ----------------------------------------
    # Extract Destination IP and Port
    # ----------------------------------------
    dst = file["full_log"].str.extract(r"->\s*(\d+\.\d+\.\d+\.\d+):(\d+)")
    file["Destination IP"] = dst[0]
    file["Destination port"] = dst[1].astype(float)

    # ----------------------------------------
    # Convert timestamp → unix timestamp
    # ----------------------------------------
    file["Unix TimeStamp"] = pd.to_datetime(file["timestamp"]).astype(np.int64) // 10**9


    # ----------------------------------------
    # Final features
    # ----------------------------------------
    # col_names = [
    #     "Priority","Unix TimeStamp","Source Port","Destination Port",
    #     "Protocol"
    # ]

    col_names = [
    "Priority",
    "Unix TimeStamp",
    "Source port",
    "Destination port",
    "Protocol"
]

    dataset = file[col_names]

    # SNORT alert → anomaly → label = 1
    labels = pd.DataFrame(np.ones(len(file), dtype=int), columns=["Class"])

    return dataset, labels


def predict_snort(json_data):
    
    result_map = {0: "benign", 1: "malicious"}
    


    # Preprocess JSON
    X_new, _ = preprocess_snort_json(json_data)

    # Scale
    X_new_scaled = scaler.transform(X_new)

    # Predict
    preds = model.predict(X_new_scaled)
    print("\nSNORT FINAL PREDICTION:")
    print(f"{result_map[preds[0]]}")
