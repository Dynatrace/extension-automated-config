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
from AuditEntryV2Handler import AuditEntryV2Handler
from math import floor
import requests
import logging
import pytz
import re

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

file_handler = logging.FileHandler('audit_config_main.log')
formatter = logging.Formatter('%(asctime)s:%(levelname)s:%(message)s')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

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
        changes = request_handler.get_dt_api_json(audit_log_endpoint)
        return changes['auditLogs']

    def get_api_version(self, audit_log_entry):
        '''
        Identify processing method required by parsing entry for API version used

        @param audit_log_entry
        '''

        entity_id_entry = str(audit_log_entry['entityId'])
        if re.match("^ME_\\w+\\: \\w+", entity_id_entry):
            return 1
        if re.match ("[a-z\\:\\[\\]\\.]", entity_id_entry):
            print (entity_id_entry, "matched API V2")
            return 2
        return 0


    def process_audit_payload(self, audit_logs):
        '''
        Process audit list and trigger annotation posting for matching Monitored Entities

        @param audit_logs - list of audit records returned from the API
        '''
        logger.addHandler(file_handler)
        audit_v1_entry = AuditEntryV1Handler()
        audit_v2_entry = AuditEntryV2Handler()
        request_handler = RequestHandler(self.url, self. headers, self.verify_ssl)
        for audit_log_entry in audit_logs:
            api_version = self.get_api_version(audit_log_entry)
            if api_version == 1:
                request_params=audit_v1_entry.extract_info(audit_log_entry, request_handler)
            elif api_version == 2:
                request_params=audit_v2_entry.extract_info(audit_log_entry, request_handler)
            else:
                logger.info(f" {audit_log_entry['logId']} ENTRY NOT MATCHED")
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
