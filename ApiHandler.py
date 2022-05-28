from abc import abstractmethod
import logging

class ApiBaseHandler():
    @abstractmethod
    def extract_info(self, audit_log_entry):
        pass

    @abstractmethod
    def post_annotation():
        pass

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