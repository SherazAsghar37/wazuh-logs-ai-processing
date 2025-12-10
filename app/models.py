import joblib

snort_scaler = joblib.load(r"./models/snort_scaler.pkl")
snort_model = joblib.load(r"./models/snort_model.pkl")

suricata_model = joblib.load("./models/rf_model.pkl")
suricata_le = joblib.load("./models/label_encoder.pkl")
suricata_scaler = joblib.load("./models/scaler.pkl")

sysmon_model = joblib.load("./models/sysmon_model88.pkl")
sysmon_label_encoders = joblib.load("./models/sysmon_label_encoders.pkl")
sysmon_target_encoder = joblib.load("./models/sysmon_target_encoder.pkl")
sysmon_scaler = joblib.load("./models/sysmon_scaler.pkl")