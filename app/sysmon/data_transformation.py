# import json
# from datetime import datetime
# import pandas as pd


# def transform_suricata_logs(json_data):
    
#         try:
#             records = []

#             log = json.loads(json_data)

#             print("log = " + log)

#             data = log.get("_source", {}).get("data", {})
#             flow = data.get("flow", {})

#             # Raw values
#             fwd_packets = int(flow.get("pkts_toserver", 0))
#             bwd_packets = int(flow.get("pkts_toclient", 0))
#             fwd_bytes = int(flow.get("bytes_toserver", 0))
#             bwd_bytes = int(flow.get("bytes_toclient", 0))

#             # Timestamps
#             start_time = flow.get("start")
#             end_time = data.get("timestamp")

#             # Derived metrics
#             duration_ms = get_flow_duration(start_time, end_time)
#             duration_s = duration_ms / 1000 if duration_ms else 1  # avoid div-by-zero

#             total_bytes = fwd_bytes + bwd_bytes
#             total_packets = fwd_packets + bwd_packets

#             record = {
#                 "Flow Duration": duration_ms,
#                 "Total Fwd Packets": fwd_packets,
#                 "Total Backward Packets": bwd_packets,
#                 "Fwd Packets Length Total": fwd_bytes,
#                 "Bwd Packets Length Total": bwd_bytes,
#                 "Flow Bytes/s": total_bytes / duration_s if duration_s else 0,
#                 "Flow Packets/s": total_packets / duration_s if duration_s else 0,
#                 "Avg Packet Size": total_bytes / total_packets if total_packets else 0,
#                 "Avg Fwd Segment Size": fwd_bytes / fwd_packets if fwd_packets else 0,
#                 "Avg Bwd Segment Size": bwd_bytes / bwd_packets if bwd_packets else 0
#             }

#             records.append(record)
#             df = pd.DataFrame(records)
#             print(df.head())
#             return df
        
#         except json.JSONDecodeError:
#             print("Skipping invalid JSON line.")
#         except Exception as e:
#             print(f"Error processing line: {e}")


# # Helper function to calculate time difference in milliseconds
# def get_flow_duration(start, end):
#     fmt = "%Y-%m-%dT%H:%M:%S.%f%z"
#     try:
#         start_dt = datetime.strptime(start, fmt)
#         end_dt = datetime.strptime(end, fmt)
#         return (end_dt - start_dt).total_seconds() * 1000  # milliseconds
#     except:
#         return None