'''
Copyright (C) George Teodorescu & Aaron Philipose - All Rights Reserved
Unauthorized copying of this file, via any medium is strictly prohibited
Proprietary and confidential
Written by George Teodorescu<george.teodorescu@dynatrace.com> and Aaron Philipose<aaron.philipose@dynatrace.com>, July 2020


Automated Configuration Audit

This tool tracks monitoring adjustments for monitored entities,
and logs the changes back to the entities' "Event" feed as an annotation.

'''
from ruxit.api.base_plugin import RemoteBasePlugin
from math import floor
import requests
import logging
import time
import os

logger = logging.getLogger(__name__)


class AuditPluginRemote(RemoteBasePlugin):
    '''
    Main class for the plugin

    @param url - Dynatrace Tenant URL
    @param apiToken - API Token for Dynatrace Tenant. Permissions - Event Feed (v1), Read Audit Logs,  Read Monitored Entities (v2)
    @param pollingInterval - How often to retreive Audit Logs from server (in minutes)
    @param verify_ssl - Boolean to choose to validate the SSL certificate of the server

    '''
    def initialize(self, **kwargs):
        '''
        Initialize the plugin with variables provided by user in the UI
        
        @param config - dictionary of all parameters needed for the class (listed in class)
        '''
        logger.info("Config: %s", self.config)
        config = kwargs['config']

        self.url = config['url'].strip()
        if self.url[-1] == '/':
            self.url = self.url[:-1]

        self.headers = {
            'Authorization': 'Api-Token ' + config['apiToken'].strip(),
        }

        self.pollingInterval = int(config['pollingInterval']) * 60 * 1000
        self.start_time = floor(time.time()*1000) - self.pollingInterval

        
        os.environ['TZ'] = config['timezone']
        time.tzset()
        logging.info(f" Timezone: {config['timezone']} and ENV: {os.environ['TZ']} and tzname {time.tzname}")

        self.verify_ssl = config['verify_ssl']
        if not self.verify_ssl:
            requests.packages.urllib3.disable_warnings()

    def make_api_request(self, http_method, endpoint, json=None):
        '''
        Make API calls with proper error handling

        @param endpoint - endpoint for Dynatrace API call
        @param json - dict payload to pass as JSON body

        @return response - response dictionary for valid API call
        '''
        while True:
            response = requests.request(http_method, f"{self.url}{endpoint}", json=json, headers=self.headers, verify=self.verify_ssl)
            if response.status_code == 429:
                logging.info("AUDIT - RATE LIMITED! SLEEPING...")
                time.sleep(response.headers['X-RateLimit-Reset']/1000000)
            else:
                break
        return response.json()

    def get_audit_logs(self):
        '''
        Retrieve API logs from the tenant

        @return audit_logs - List of changes recorded from the audit API
        '''
        audit_log_endpoint = f"/api/v2/auditlogs?filter=eventType(CREATE,UPDATE)&from={self.start_time}&to={self.end_time}&sort=timestamp"
        changes = self.make_api_request("GET", audit_log_endpoint)
        return changes['auditLogs']

    def post_annotations(self, eventType, user, category, timestamp, entityId, patch):
        '''
        Post annotation to event feed for the provided EntityID

        @param eventType - Type of event that triggered Audit Log (CREATE/UPDATE)
        @param user - User that made the action
        @param category - Audit Category
        @param timestamp - Unix Epoch time when the change was made
        @param entityId - Entity that was affected by the creation/update
        @param patch - Exact option or feature that was changed and it's old value

        '''
        is_managed = True if "/e/" in self.url else False
        event_endpoint = "/api/v1/events"
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
                "Timestamp": time.strftime("%a, %d %b %Y %H:%M:%S %z", time.localtime(timestamp/1000)),
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
        response = self.make_api_request("POST", event_endpoint, json=payload)
        logging.info(
            f"AUDIT - MATCHED: {user} {eventType} {category} {timestamp} {entityId}")
        logging.info(f"AUDIT - POST RESPONSE: {response}")

    def get_processes_from_group(self, process_group_id):
        '''
        Get all the Process Group Instances from a Process Group change

        @param process_group_id - Process Group that needs to be investigated

        @return pgi_list - List of Process Group Instances that belong to Process Group
        '''
        logging.info(f"Entity ID: {process_group_id}")
        monitored_entities_endpoint = f"/api/v2/entities/{process_group_id}?fields=toRelationships.isInstanceOf"
        pg_details = self.make_api_request("GET", monitored_entities_endpoint)
        pgi_list = []
        logging.info(f"PG JSON - {pg_details}")
        for relationship in pg_details['toRelationships']['isInstanceOf']:
            if relationship['type'] == "PROCESS_GROUP_INSTANCE":
                pgi_list.append(relationship['id'])
        return pgi_list

    def process_audit_payload(self, audit_logs):
        '''
        Process audit list and trigger annotation posting for matching Monitored Entities

        @param audit_logs - list of audit records returned from the API
        '''
        for x in range(len(audit_logs)):
            eventType = str(audit_logs[x]['eventType'])
            user = str(audit_logs[x]['user'])
            category = str(audit_logs[x]['category'])
            timestamp = int(audit_logs[x]['timestamp'])
            entityId = str(audit_logs[x]['entityId']).rsplit(maxsplit=1)[1]
            entityType = str(audit_logs[x]['entityId']).split(maxsplit=1)[0]
            patch = str(audit_logs[x]['patch'])
            # If entityId beings with ME_ then proceed to extract the real entityId by replacing the match with nothing
            if entityType.startswith("ME_PROCESS_GROUP:") and user != "agent quotas worker":
                pgi_list = self.get_processes_from_group(entityId)
                for pgi in pgi_list:
                    self.post_annotations(
                        eventType, user, category, timestamp, pgi, patch)
            elif entityType.startswith("ME_") and user != "agent quotas worker":
                self.post_annotations(
                    eventType, user, category, timestamp, entityId, patch)
            else:
                logging.info(
                    f"AUDIT - NOT MATCHED: {user} {eventType} {category} {timestamp} {entityId}")
        logging.info(
            f"AUDIT - CHANGES FOUND BETWEEN {self.start_time} & {self.end_time} = {len(audit_logs)}")

    def query(self, **kwargs):
        '''
        Routine call from the ActiveGate
        '''
        self.end_time = floor(time.time()*1000)
        if self.end_time - self.start_time >= self.pollingInterval:
            audit_logs = self.get_audit_logs()
            self.process_audit_payload(audit_logs)
            self.start_time = self.end_time + 1