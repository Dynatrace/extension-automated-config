from RequestHandler import RequestHandler
import logging

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
    def extract_info(self, audit_log_entry, request_handler : 'RequestHandler'):
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

    def get_processes_from_group(self, process_group_id, request_handler : 'RequestHandler'):
        '''
        Get all the Process Group Instances from a Process Group change

        @param process_group_id - Process Group that needs to be investigated

        @return pgi_list - List of Process Group Instances that belong to Process Group
        '''
        logger.info(f"Entity ID: {process_group_id}")
        monitored_entities_endpoint = f"/api/v2/entities/{process_group_id}?fields=toRelationships.isInstanceOf"
        pg_details = request_handler.get_dt_api_json(monitored_entities_endpoint)
        pgi_list = []
        for relationship in pg_details['toRelationships']['isInstanceOf']:
            if relationship['type'] == "PROCESS_GROUP_INSTANCE":
                pgi_list.append(relationship['id'])
        return pgi_list

    def process_group_instance_to_entity_str(self, pgi_list):
        all_instances_str = ""
        for process_group_instance in pgi_list:
            all_instances_str = f"{all_instances_str}\"{process_group_instance}\","
        if len(all_instances_str) > 0:
            all_instances_str = all_instances_str[:-1]
        pgi_list_str = f"{all_instances_str}"
        logger.info(f"PGI STRING: {pgi_list_str}")
        return pgi_list_str
