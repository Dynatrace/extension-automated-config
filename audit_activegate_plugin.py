from ruxit.api.base_plugin import RemoteBasePlugin
import re
import requests
import logging
import json

logger = logging.getLogger(__name__)


class AuditPluginRemote(RemoteBasePlugin):
    pollCount = 1

    def initialize(self, **kwargs):
        logger.info("Config: %s", self.config)
        config = kwargs['config']
        self.url = config['url'].strip()
        self.apiToken = config['apiToken'].strip()
        self.pollingInterval = config['pollingInterval']

    def query(self, **kwargs):
        if self.pollCount < self.pollingInterval:
            self.pollCount += 1
            return
        self.pollCount = 1
        self.run_audit(self.url, self.apiToken, self.pollingInterval)

    def run_audit(self, url, apiToken, timeInterval=5):
        if url[-1] == '/':
            url = url[:-1]

        is_managed = True if "live.dynatrace.com" not in url else False
        eventAPI = url + "/api/v1/events"
        auditLogAPI = url + \
            f"/api/v2/auditlogs?filter=eventType(CREATE,UPDATE)&from=now-{timeInterval}m"
        payload = {}
        headers = {
            'Authorization': 'Api-Token ' + apiToken,
            'content-type': "application/json"
        }

        response = requests.request(
            "GET", auditLogAPI, headers=headers, data=payload, verify=False)

        changes = response.json()
        logging.info("URL USED: " + auditLogAPI)
        logging.info("GET RESPONSE: " + response.text)
        auditLogs = changes['auditLogs']
        x = 0
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
                            "eventType": eventType,
                            "User": user,
                            "Category": category,
                            "Timestamp": timestamp,
                            "entityId": entityId
                        },
                        "source": "Automated Configuration Audit",
                        "annotationType": "Dynatrace Configuration Change",
                        "annotationDescription": " ",
                        "description": "Dynatrace Configuration Change"
                    }
                    if is_managed:
                        managed_domain = re.search(
                            r'^(https\:\/\/[^\/]*)', url).group(1)
                        logging.info(f"DOMAIN FOUND: {managed_domain}")
                        payload['customProperties']['User Link'] = f"{managed_domain}/cmc#cm/users/userdetails;uuid={user}"
                    logging.info(json.dumps(payload))
                    response = requests.request(
                        "POST", eventAPI, json=payload, headers=headers, verify=False)
                    logging.info("MATCHED: " + user + " " + eventType +
                                 " " + category + " " + timestamp + " " + entityId)
                    logging.info("POST RESPONSE: " + response.text)
            else:
                logging.info("NOT MATCHED: " + user + " " + eventType +
                             " " + category + " " + timestamp + " " + entityId)
        else:
            logging.info("NO RECENT CHANGES FOUND!")
