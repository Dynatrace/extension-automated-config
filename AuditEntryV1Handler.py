"""Processing audit entry information that is formatted in V1 style
"""
from RequestHandler import RequestHandler # pylint: disable=unused-import
from AuditEntryBaseHandler import AuditEntryBaseHandler

class AuditEntryV1Handler(AuditEntryBaseHandler):
    """Class to process V1 formatted audit log entries

    Args:
        AuditEntryBaseHandler (Class): Parent Class for shared operations
    """
    def extract_info(self, audit_log_entry, request_handler : 'RequestHandler'):
        """Extract info for annotations and processing from audit entry

        Args:
            audit_log_entry (dict): singular audit log entry from audit list
            request_handler (RequestHandler): Request Handler to use in case expansion is needed

        Returns:
            dict: dict with entity_id and properties dict nested
        """
        annotation_data = super().extract_info(audit_log_entry, request_handler)
        entity_id = str(audit_log_entry['entityId']).rsplit(maxsplit=1)[1]
        entity_type = str(audit_log_entry['entityId']).split(maxsplit=1)[0]
        annotation_data ['entityId'] = f"\"{entity_id}\""

        if entity_type.startswith("ME_PROCESS_GROUP:"):
            pgi_list = self.get_processes_from_group(entity_id, request_handler)
            pgi_str = self.process_group_instance_to_entity_str(pgi_list)
            annotation_data ['entityId'] = pgi_str
        if entity_type.startswith("ME_"):
            return annotation_data
