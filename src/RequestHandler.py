# Copyright 2022 Dynatrace LLC

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Request Handler for making API calls to Dynatrace
"""
from time import sleep
import logging
import requests

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class RequestHandler():
    """Request Handler for making API calls to Dynatrace
    """
    def __init__(self, base_url, headers, verify_ssl=True):
        self.url = base_url
        self.headers = headers
        self.verify_ssl = verify_ssl

    def get_dt_api_json(
            self,
            endpoint: str,
            json_payload: dict = None,
            params: dict = None
    ) -> dict:
        """Get JSON response from DT API

        Args:
            endpoint (str): Endpoint to query from Dynatrace
            json_payload (dict, optional): JSON data to send. Defaults to None.
            params (dict, optional): Param data to send. Defaults to None.

        Returns:
            dict: JSON response from Dynatrace API endpoint
        """
        response = self.make_dt_api_request("GET", endpoint, json_payload, params)
        return response.json()

    def make_dt_api_request(
            self,
            http_method,
            endpoint,
            json_payload=None,
            params=None
    ) -> requests.Response:
        '''
        Make API calls with proper error handling

        @param endpoint - endpoint for Dynatrace API call
        @param json_payload - dict payload to pass as JSON body

        @return response - response dictionary for valid API call
        #TODO - ADAPT DOCSTRING TO NEW FORMAT
        '''
        while True:
            response = requests.request(
                    http_method,
                    f"{self.url}{endpoint}",
                    json=json_payload,
                    headers=self.headers,
                    verify=self.verify_ssl,
                    params=params
            )
            if response.status_code == 429:
                logger.info("[RequestHandler] AUDIT - RATE LIMITED! SLEEPING...")
                sleep(response.headers['X-RateLimit-Reset']/1000000)
            else:
                break
        return response

    def post_annotations(self, entity_id: str, properties: dict) -> None:
        """Post annoations to Dynatrace entity event log

        Args:
            entity_id (str): Entity ID to post update
            properties (dict): All info needed to post in the annotation
        """
        endpoint = "/api/v2/events/ingest"
        json_payload = {
            "eventType": "CUSTOM_ANNOTATION",
            "title" : "Automated Configuration Audit",
            "timeout": 0,
            "entitySelector": f"entityId ({entity_id})",
            "properties": properties
        }
        response = self.make_dt_api_request("POST", endpoint, json_payload=json_payload)
        logger.info(
                "[RequestHandler] Annotation for LOG_ID: %s,ENTITY_ID:%s : %s",
                json_payload['properties']['logId'],
                entity_id,
                response.status_code
        )
        logger.debug("[RequestHandler] Requests: %s", response.request)
        logger.debug("[RequestHandler] Request Text: %s", response.text)
