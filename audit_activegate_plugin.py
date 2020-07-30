from ruxit.api.base_plugin import RemoteBasePlugin
from math import floor
import requests
import logging
import time

logger = logging.getLogger(__name__)


class AuditPluginRemote(RemoteBasePlugin):
    start_time = 1
    end_time = 1

    def initialize(self, **kwargs):
        logger.info("Config: %s", self.config)
        config = kwargs['config']
        self.url = config['url'].strip()
        self.apiToken = config['apiToken'].strip()
        self.pollingInterval = int(config['pollingInterval']) * 60 * 1000
        self.start_time = floor(time.time()*1000) - self.pollingInterval
        self.verify_ssl = config['verify_ssl']
        if not self.verify_ssl:
            requests.packages.urllib3.disable_warnings()

    def query(self, **kwargs):
        self.end_time = floor(time.time()*1000)
        if self.end_time - self.start_time >= self.pollingInterval:
            self.run_audit()
            logging.info(
                f"AUDIT - RUN INTERVAL: START -> {self.start_time} END -> {self.end_time}")
            self.start_time = self.end_time + 1

    def run_audit(self):
        if self.url[-1] == '/':
            self.url = self.url[:-1]

        is_managed = True if "/e/" in self.url else False
        eventAPI = self.url + "/api/v1/events"
        auditLogAPI = self.url + \
            f"/api/v2/auditlogs?filter=eventType(CREATE,UPDATE)&from={self.start_time}&to={self.end_time}"
        payload = {}
        headers = {
            'Authorization': 'Api-Token ' + self.apiToken,
            'content-type': "application/json"
        }

        response = requests.request(
            "GET", auditLogAPI, headers=headers, data=payload, verify=self.verify_ssl)

        changes = response.json()
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
                patch = str(auditLogs[x]['patch'])
                # If entityId beings with ME_ then proceed to extract the real entityId by replacing the match with nothing
                if entityId.startswith("ME_") and user != "agent quotas worker":
                    entityId = entityId.rsplit(maxsplit=1)[1]
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
                            "entityId": entityId,
                            "Change": patch
                        },
                        "source": "Automated Configuration Audit",
                        "annotationType": "Dynatrace Configuration Change",
                        "annotationDescription": " ",
                        "description": "Dynatrace Configuration Change",
                    }
                    if is_managed:
                        managed_domain = self.url.split(sep="/e/")[0]
                        payload['customProperties'][
                            'User Link'] = f"{managed_domain}/cmc#cm/users/userdetails;uuid={user}"
                    response = requests.request(
                        "POST", eventAPI, json=payload, headers=headers, verify=self.verify_ssl)
                    logging.info(f"AUDIT - MATCHED: {user} {eventType} {category} {timestamp} {entityId}")
                    logging.info(f"AUDIT - POST RESPONSE: {response.text}")
            else:
                logging.info(f"AUDIT - NOT MATCHED: {user} {eventType} {category} {timestamp} {entityId}")
        else:
            logging.info(f"AUDIT - NO RECENT CHANGES FOUND! BETWEEN {self.start_time} & {self.end_time}")
