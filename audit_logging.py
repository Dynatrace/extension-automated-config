# [Non-Prod] Env API v2
# Runs as a cronjob that pulls the latest configuration changes done every 5 mins and posts an event to that entity
# 
import requests
import re
import logging

def run_audit(domain, tenant, apiToken, timeInterval=5):
  tenantUrl = domain + "/e/" + tenant
  eventAPI = tenantUrl + "/api/v1/events"
  auditLogAPI = tenantUrl + f"/api/v2/auditlogs?filter=eventType(CREATE,UPDATE)&from=now-{timeInterval}m"
  payload = {}
  headers = {
      'Authorization': 'Api-Token ' + apiToken,
      'content-type': "application/json"
  }

  response = requests.request("GET", auditLogAPI, headers=headers, data = payload, verify=False)

  changes = response.json()
  logging.info("URL USED: " + auditLogAPI)
  logging.info("GET RESPONSE: " + response.text)
  auditLogs = changes['auditLogs']
  x=0
  # GET audit log for config changes
  if len(auditLogs) > 0:
    for x in range(len(auditLogs)):
      eventType = str(auditLogs[x]['eventType'])
      user = str(auditLogs[x]['user'])
      category = str(auditLogs[x]['category'])
      timestamp = str(auditLogs[x]['timestamp'])
      entityId = str(auditLogs[x]['entityId'])
      # If entityId beings with ME_ then proceed to extract the real entityId by replacing the match with nothing
      if re.match("ME_", entityId) and user != "agent quotas worker":
        entityId = re.sub(r'(.*)\s', '', entityId)
        payload = {  
            "eventType": "CUSTOM_ANNOTATION",
            "start": 0,
            "end": 0,
            "timeoutMinutes": 0,
            "attachRules": {
                "entityIds": [entityId]
            },
            "customProperties": {
                "eventType":eventType,
                "User":user,
                "User Link": domain + "/cmc#cm/users/userdetails;uuid=" + user,
                "Category":category,
                "Timestamp":timestamp,
                "entityId":entityId
            },
            "source": "Automated Configuration Audit",
            "annotationType": "Dynatrace Configuration Change",
            "annotationDescription": " ",
            "description": "Dynatrace Configuration Change"
        }
        response = requests.request("POST", eventAPI, json=payload, headers=headers, verify=False)
        logging.info("MATCHED: " + user + " " + eventType + " " + category + " " + timestamp + " " + entityId)
        logging.info("POST RESPONSE: " + response.text)
      else:
        logging.info("NOT MATCHED: " + user + " " + eventType + " " + category + " " + timestamp + " " + entityId)
        continue
  else:
    logging.info("NO RECENT CHANGES FOUND!")