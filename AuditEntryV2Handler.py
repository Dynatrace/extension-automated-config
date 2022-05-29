import re
from RequestHandler import RequestHandler
from AuditEntryBaseHandler import AuditEntryBaseHandler

class AuditEntryV2Handler(AuditEntryBaseHandler):
    def extract_info(self, audit_log_entry, request_handler: 'RequestHandler'):
        annotation_data = super().extract_info(audit_log_entry, request_handler)
        entity_regex = re.search("^([a-z]+\\:[a-z\\.\\-]+) \\(([A-Z0-9\\-\\_]+)\\)\\:", str(audit_log_entry['entityId']))
        entity_id = entity_regex.group(2)
        entity_type = entity_regex.group(1)
        annotation_data ['entityId'] = f"\"{entity_id}\""
        annotation_data ['properties']['entityType'] = entity_type
        # If entityId beings with PROCESS_GROUP then proceed to extract the real entityId by replacing the match with nothing
        if entity_id.startswith("PROCESS_GROUP-"):
            pgi_list = self.get_processes_from_group(entity_id, request_handler)
            pgi_str = self.process_group_instance_to_entity_str(pgi_list)
            annotation_data ['entityId'] = pgi_str
        return annotation_data