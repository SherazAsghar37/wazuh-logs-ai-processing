from datetime import datetime
import httpx  
import ssl

async def execute_test_script():
    try:
        alert = {
            "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "rule": {
                "level": 5,
                "id": "100001",
                "description": "Modified Wazuh alert"
            },
            "agent": {
                "id": "001",
                "name": "my-agent"
            },
            "manager": {
                "name": "wazuh-manager"
            },
            "full_log": "This is a modified alert injected into OpenSearch.",
            "decoder": {
                "name": "json"
            },
            "input": {
                "type": "log"
            },
            "location": "custom-injection",
            "custom": True
        }
        
       
        async with httpx.AsyncClient(verify=False) as client:
            res = await client.post(
                "https://192.168.1.105:9200/wazuh-alerts-4.x-2025.08.17/_doc",  
                json=alert,
                auth=('admin', 'admin') 
            )
        
        print(res.status_code, res.text)
        return res
        
    except Exception as e:
        print(f"Error executing test script: {e}")
        raise