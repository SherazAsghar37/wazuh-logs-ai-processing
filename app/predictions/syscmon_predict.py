import joblib
# from app.models import sysmon_scaler as scaler
# from app.models import sysmon_model as model
# from app.models import sysmon_label_encoders as label_encoders
# from app.models import sysmon_target_encoder as target_encoder


sysmon_event_dict = {
    1.0: "Process creation — logs when a new process starts",
    3.0: "Network connection detected — logs TCP/UDP connections made by processes",
    5.0: "Process termination — logs when a process ends",
    7.0: "Image (module/DLL) loaded — logs when a process loads a module or DLL",
    10.0: "Process access — logs when one process opens/interacts with another process",
    11.0: "File created / overwritten — logs file creation or modification",
    13.0: "Registry value set — logs when a registry value is modified/created",
    22.0: "DNS query — logs when a process performs a DNS lookup",
    23.0: "File delete — logs when a file is deleted (with archival depending on config)"
}


model = joblib.load("./models/sysmon_model88.pkl")
label_encoders = joblib.load("./models/sysmon_label_encoders.pkl")
target_encoder = joblib.load("./models/sysmon_target_encoder.pkl")
scaler = joblib.load("./models/sysmon_scaler.pkl")

def safe_get(obj, *keys):
    for key in keys:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(key)
        if obj is None:
            return None
    return obj

def clean(value):
    return 0 if value is None else value

def ipv6_check(ip):
    return 1 if (ip and ":" in ip) else 0.0

def extract(log):
    eventdata = safe_get(log, "_source", "data", "win", "eventdata")
    system = safe_get(log, "_source", "data", "win", "system")

    return {
        "Image": clean(safe_get(eventdata, "Image") or safe_get(eventdata, "ImageLoaded") or safe_get(eventdata, "p1")),
        "ProcessId": clean(safe_get(eventdata, "ProcessId") or safe_get(system, "processID")),
        "User": clean(safe_get(eventdata, "User")),
        "Protocol": clean(safe_get(eventdata, "Protocol")),
        "Initiated": clean(safe_get(eventdata, "Initiated")),
        "SourceIp": clean(safe_get(eventdata, "SourceIp")),
        "SourcePort": clean(safe_get(eventdata, "SourcePort")),
        "DestinationIp": clean(safe_get(eventdata, "DestinationIp")),
        "DestinationPort": clean(safe_get(eventdata, "DestinationPort")),
        "DestinationPortName": clean(safe_get(eventdata, "DestinationPortName")),
        "SourceHostname": clean(safe_get(eventdata, "SourceHostname") or safe_get(log, "_source", "agent", "name")),
        "SourceIsIpv6": ipv6_check(safe_get(eventdata, "SourceIp")),
        "DestinationIsIpv6": ipv6_check(safe_get(eventdata, "DestinationIp")),
        "Computer": clean(safe_get(system, "computer"))
    }


def predict_sysmon(df):
  # =============== ENCODE CATEGORICAL COLUMNS ===============
  for col in df.columns:
      if col in label_encoders:
          df[col] = df[col].astype(str)
          le = label_encoders[col]
          # Map unknown values to a special integer
          df[col] = df[col].apply(lambda x: le.transform([x])[0] if x in le.classes_ else -1)


  # # =============== SCALE NUMERIC COLUMNS ===============
  df_scaled = scaler.transform(df)

  # # =============== PREDICT ===============
  pred = model.predict(df_scaled)
  decoded = target_encoder.inverse_transform(pred)

  print("\nSYSMON FINAL PREDICTION:")
  print(sysmon_event_dict.get(decoded[0]))