from AuditEntryBaseHandler import AuditEntryBaseHandler
import re
import logging

class AuditEntryV2Handler(AuditEntryBaseHandler):
    def extract_info(self, audit_log_entry):
        event_type = str(audit_log_entry['eventType'])
        user = str(audit_log_entry['user'])
        category = str(audit_log_entry['category'])
        timestamp = int(audit_log_entry['timestamp'])
        patch = str(audit_log_entry['patch'])
        entity_regex = re.search("^([a-z]+\\:[a-z\\.\\-]+) \\(([A-Z0-9\\-]+)\\)\\:", str(audit_log_entry['entityId']))
        entity_id = entity_regex.group(2)
        entity_type = entity_regex.group(1)
        logging.info(f"{entity_id} - ENTITY ID, {entity_type} - ENTITY TYPE")
        results = {
            'entityId' : entity_id,
            'properties' : {
              "eventType" : event_type,
              "user" : user,
              "category" : category,
              "timestamp": timestamp,
              "patch" : patch,
            }
        }
        logging.info(results)
        logging.info(entity_id)
        # If entityId beings with ME_ then proceed to extract the real entityId by replacing the match with nothing
        if entity_id.startswith("PROCESS_GROUP-:") and user != "agent quotas worker":
            pgi_list = self.get_processes_from_group(entity_id)
            results ['entityId'] = pgi_list
        return results