from app.config import SURICATA_LOGS_PATH,SNORT_LOGS_PATH

def is_suricata(alert: dict) -> bool:
    location = alert.get("location")
    if(location==SURICATA_LOGS_PATH ):
        return True
    return False
    
def is_sysmon(alert: dict) -> bool:
    groups = alert.get("rule",{}).get("groups",[])
    if("sysmon" in groups):
        return True
    return False

def is_snort(alert: dict) -> bool:
    location = alert.get("location")
    if(location==SNORT_LOGS_PATH ):
        return True
    return False