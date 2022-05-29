from RequestHandler import RequestHandler
from AuditEntryBaseHandler import AuditEntryBaseHandler

class AuditEntryV1Handler(AuditEntryBaseHandler):
    def extract_info(self, audit_log_entry, request_handler : 'RequestHandler'):
        annotation_data = super().extract_info(audit_log_entry, request_handler)
        entityId = str(audit_log_entry['entityId']).rsplit(maxsplit=1)[1]
        entityType = str(audit_log_entry['entityId']).split(maxsplit=1)[0]
        annotation_data ['entityId'] = f"\"{entityId}\""

        # If entityId beings with ME_ then proceed to extract the real entityId by replacing the match with nothing
        if entityType.startswith("ME_PROCESS_GROUP:") and annotation_data['properties']['user'] != "agent quotas worker":
            pgi_list = self.get_processes_from_group(entityId, request_handler)
            pgi_str = self.process_group_instance_to_entity_str(pgi_list)
            annotation_data ['entityId'] = pgi_str
        if entityType.startswith("ME_") and annotation_data['properties']['user'] != "agent quotas worker":
            return annotation_data
