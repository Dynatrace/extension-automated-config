from time import sleep
import requests
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

file_handler = logging.FileHandler('audit_config_requesthandler.log')
formatter = logging.Formatter('%(asctime)s:%(levelname)s:%(message)s')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

class RequestHandler(object):
    def __init__(self, base_url, headers, verify_ssl=True):
        self.url = base_url
        self.headers = headers
        self.verify_ssl = verify_ssl

    def get_dt_api_json(self, endpoint, json_payload=None, params=None) -> dict:
        response = self.make_dt_api_request("GET", endpoint, json_payload, params)
        return response.json()

    def make_dt_api_request(self, http_method, endpoint, json_payload=None, params=None) -> requests.Response:
        '''
        Make API calls with proper error handling

        @param endpoint - endpoint for Dynatrace API call
        @param json_payload - dict payload to pass as JSON body

        @return response - response dictionary for valid API call
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
                logger.info("AUDIT - RATE LIMITED! SLEEPING...")
                sleep(response.headers['X-RateLimit-Reset']/1000000)
            else:
                break
        return response

    def post_annotations(self, entity_id: str, properties: dict) -> None:
        
        endpoint = "/api/v2/events/ingest"
        json_payload = {
            "eventType": "CUSTOM_ANNOTATION",
            "title" : "Automated Configuration Audit2",
            "timeout": 0,
            "entitySelector": f"entityId ({entity_id})",
            "properties": properties
        }
        response = self.make_dt_api_request("POST", endpoint, json_payload=json_payload)
        logger.info(f"Annotation for LOG_ID:{json_payload['properties']['logId']},ENTITY_ID:{entity_id} : {response.status_code}")
        logger.debug(f"Requests:\n{response.request}")
        logger.debug(f"{response.text}")
