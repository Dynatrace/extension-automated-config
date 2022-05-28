# Copyright 2020 Dynatrace LLC

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

'''
Automated Configuration Audit

This tool tracks monitoring adjustments for monitored entities,
and logs the changes back to the entities' "Event" feed as an annotation.

'''
from ruxit.api.base_plugin import RemoteBasePlugin
from datetime import datetime
from RequestHandler import RequestHandler
from AuditEntryV1Handler import AuditEntryV1Handler
from math import floor
from time import sleep
import requests
import logging
import pytz
import re

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

        self.timezone = pytz.timezone(config['timezone'])
        self.start_time = floor(datetime.now().timestamp()*1000) - self.pollingInterval
        self.verify_ssl = config['verify_ssl']
        if not self.verify_ssl:
            requests.packages.urllib3.disable_warnings()

    def get_audit_logs(self):
        '''
        Retrieve API logs from the tenant

        @return audit_logs - List of changes recorded from the audit API
        '''
        request_handler = RequestHandler(self.url, self. headers, self.verify_ssl)
        audit_log_endpoint = f"/api/v2/auditlogs?filter=eventType(CREATE,UPDATE)&from={self.start_time}&to={self.end_time}&sort=timestamp"
        changes = request_handler.get_dt_api_json("GET", audit_log_endpoint)
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
        request_handler = RequestHandler(self.url, self. headers, self.verify_ssl)
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
                "Timestamp": datetime.now(tz=self.timezone).strftime("%a, %d %b %Y %H:%M:%S %z"),
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
        response = request_handler.get_dt_api_json("POST", event_endpoint, json_payload=payload)
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
        request_handler = RequestHandler(self.url, self. headers, self.verify_ssl)
        monitored_entities_endpoint = f"/api/v2/entities/{process_group_id}?fields=toRelationships.isInstanceOf"
        pg_details = request_handler.get_dt_api_json("GET", monitored_entities_endpoint)
        pgi_list = []
        logging.info(f"PG JSON - {pg_details}")
        for relationship in pg_details['toRelationships']['isInstanceOf']:
            if relationship['type'] == "PROCESS_GROUP_INSTANCE":
                pgi_list.append(relationship['id'])
        return pgi_list

    def get_api_version(self, audit_log_entry):
        '''
        Identify processing method required by parsing entry for API version used

        @param audit_log_entry
        '''

        entityType = str(audit_log_entry)
        if re.match("^ME_\\w+\\: \\w+", entityType):
            return 1
        if re.match ("[a-z\\:\\[\\]\\.]", entityType):
            print (entityType, "matched API V2")
            return 2
        return 0


    def process_audit_payload(self, audit_logs):
        '''
        Process audit list and trigger annotation posting for matching Monitored Entities

        @param audit_logs - list of audit records returned from the API
        '''
        audit_v1_entry = AuditEntryV1Handler()
        request_handler = RequestHandler(self.url, self. headers, self.verify_ssl)
        for audit_log_entry in audit_logs:
            request_params=audit_v1_entry.extract_info(audit_log_entry)
            request_handler.post_annotations(request_params['entityId'], request_params['properties'])
            

    def query(self, **kwargs):
        '''
        Routine call from the ActiveGate
        '''
        self.end_time = floor(datetime.now().timestamp()*1000)
        if self.end_time - self.start_time >= self.pollingInterval:
            audit_logs = self.get_audit_logs()
            self.process_audit_payload(audit_logs)
            self.start_time = self.end_time + 1
