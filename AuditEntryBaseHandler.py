"""
Library for Base Audit Entry Handler
"""
import logging
from typing import List
from RequestHandler import RequestHandler # pylint: disable=unused-import

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

file_handler = logging.FileHandler('audit_config_auditbasehandler.log')
formatter = logging.Formatter('%(asctime)s:%(levelname)s:%(message)s')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

class AuditEntryBaseHandler():
    '''
    Base Class for Audit Entry to be Processed and Pushed.
    Should only be used by child classes.
    '''
    def extract_info(
            self,
            audit_log_entry: str,
            request_handler : 'RequestHandler' # pylint: disable=unused-argument
    ) -> dict:
        """Extract info for annotations and processing from audit entry

        Args:
            audit_log_entry (str): _description_
            request_handler (RequestHandler): _description_

        Returns:
            _type_: _description_
        """
        event_type = str(audit_log_entry['eventType'])
        user = str(audit_log_entry['user'])
        category = str(audit_log_entry['category'])
        timestamp = int(audit_log_entry['timestamp'])
        patch = str(audit_log_entry['patch'])
        log_id = str(audit_log_entry['logId'])
        # Adding placeholder to reseverve order in dict
        annotation_data = {
            'properties' : {
              "eventType" : event_type,
              "user" : user,
              "category" : category,
              "timestamp": timestamp,
              "patch" : patch,
              "logId": log_id,
            }
        }
        return annotation_data

    def get_processes_from_group(
            self,
            process_group_id: str,
            request_handler : 'RequestHandler'
    ) -> List[str]:
        """Get all the Process Group Instances from a Process Group change

        Args:
            process_group_id (str): Process Group that needs to be investigated
            request_handler (RequestHandler): Request Handler to query API

        Returns:
            List[str]: List of progress group instances from progress group entity
        """
        logger.info("Entity ID: %(process_group_id)s")
        monitored_entities_endpoint = \
                f"/api/v2/entities/{process_group_id}?fields=toRelationships.isInstanceOf"
        pg_details = request_handler.get_dt_api_json(monitored_entities_endpoint)
        pgi_list = []
        for relationship in pg_details['toRelationships']['isInstanceOf']:
            if relationship['type'] == "PROCESS_GROUP_INSTANCE":
                pgi_list.append(relationship['id'])
        return pgi_list

    def process_group_instance_to_entity_str(
            self,
            pgi_list: List[str]
    ) -> str:
        """Takes a process group instance list returns in one string

        Args:
            pgi_list (List[str]): List of progress group instances

        Returns:
            str: All process groups, comma seperated
        """
        all_instances_str = ""
        for process_group_instance in pgi_list:
            all_instances_str = f"{all_instances_str}\"{process_group_instance}\","
        if len(all_instances_str) > 0:
            all_instances_str = all_instances_str[:-1]
        pgi_list_str = f"{all_instances_str}"
        logger.info("PGI STRING: %(pgi_list_str)s")
        return pgi_list_str

    def get_all_entities(
            self,
            entity_id: str,
            request_handler: 'RequestHandler'
    ) -> str:
        """Checks Entity if it needs to be exploded into a list of entities

        Args:
            entity_id (str): singular entity_id
            request_handler (RequestHandler): Request Handler to query API

        Returns:
            str: singular entity_id or list of entity_ids strung
        """
        if entity_id.startswith("PROCESS_GROUP-"):
            pgi_list = self.get_processes_from_group(entity_id, request_handler)
            entity_id = self.process_group_instance_to_entity_str(pgi_list)
        return entity_id
