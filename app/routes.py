from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from app.send_script import execute_test_script
from app.utils import is_suricata,is_sysmon,is_snort
import json
import joblib
from app.predictions.suricata_predict import predict_suricata
from app.predictions.syscmon_predict import extract, predict_sysmon
from app.predictions.snort_predict import predict_snort
import pandas as pd
# from app.models import suricata_model, suricata_le, suricata_scaler




wazuh = APIRouter(prefix="/wazuh-data", tags=["wazuh"])


@wazuh.post("/alert")
async def wazuh_alert(request: Request):
    try:
        data = await request.json() 
        if(is_suricata(data)):
            clf = joblib.load("./models/rf_model.pkl")
            le = joblib.load("./models/label_encoder.pkl")
            scaler = joblib.load("./models/scaler.pkl")
            result =  predict_suricata(data,scaler,clf,le)
            print("Model loaded successfully!",  result)
        elif(is_sysmon(data)):
            logs = [data] if isinstance(data, dict) else data
            records = [extract(l) for l in logs]
            print("records ",records)
            df = pd.DataFrame(records)
            result = predict_sysmon(df)
        # elif(is_snort(data)):
        #     predict_snort(data)
            

        # print("Received Wazuh alert data:", data)
       
        return JSONResponse(
            status_code=200,
            content={
                "status": "success",
                "message": "Webhook data received successfully"
            }
        )
    except Exception as e:
        print("❌ Error handling Wazuh data:", e)
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": f"Exception: {str(e)}"
            }
        )

@wazuh.get("/execute-test-script")
async def execute_test():
    try:
        res = execute_test_script()  # Assuming this function exists
        return JSONResponse(
            status_code=200,
            content={
                "status": "success",
                "message": "Test script executed successfully",
                "response": res.text,
                "status_code": res.status_code
            }
        )
    except Exception as e:
        print("❌ Error handling Wazuh data:", e)
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": f"Exception: {str(e)}"
            }
        )