from time import sleep
import requests
import logging

class RequestHandler:
    def __init__(self, base_url, headers, verify_ssl=True):
        self.url = base_url
        self.headers = headers
        self.verify_ssl = verify_ssl

    def get_dt_api_json(self, http_method, endpoint, json_payload=None, params=None):
        response = self.make_dt_api_request("GET", endpoint, json_payload, params)
        return response.json()

    def make_dt_api_request(self, http_method, endpoint, json_payload=None, params=None):
        '''
        Make API calls with proper error handling

        @param endpoint - endpoint for Dynatrace API call
        @param json_payload - dict payload to pass as JSON body

        @return response - response dictionary for valid API call
        '''
        while True:
            response = requests.request(http_method, f"{self.url}{endpoint}", json=json_payload, headers=self.headers, verify=self.verify_ssl, params=params)
            if response.status_code == 429:
                logging.info("AUDIT - RATE LIMITED! SLEEPING...")
                sleep(response.headers['X-RateLimit-Reset']/1000000)
            else:
                break
        return response

    def post_annotations(self, entity_id: str, properties: dict):
        
        endpoint = "/api/v2/events/ingest"
        json_payload = {
            "eventType": "CUSTOM_ANNOTATION",
            "title" : "Automated Configuration Audit2",
            "timeout": 0,
            "entitySelector": f"entityId (\"{entity_id}\")",
            "properties": properties
        }
        response = self.make_dt_api_request("POST", endpoint, json_payload=json_payload)
        logging.info(f"Annotation for {entity_id} : {response.status_code}")
