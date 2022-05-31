"""Processing audit entry information that is formatted in V1 style
"""
import re
from RequestHandler import RequestHandler # pylint: disable=unused-import
from AuditEntryBaseHandler import AuditEntryBaseHandler

class AuditEntryV2Handler(AuditEntryBaseHandler):
    """Class to process V1 formatted audit log entries

    Args:
        AuditEntryBaseHandler (Class): Parent Class for shared operations
    """
    def extract_info(self, audit_log_entry, request_handler: 'RequestHandler'):
        """Extract info for annotations and processing from audit entry

        Args:
            audit_log_entry (dict): singular audit log entry from audit list
            request_handler (RequestHandler): Request Handler to use in case expansion is needed

        Returns:
            dict: dict with entity_id and properties dict nested
        """
        annotation_data = super().extract_info(audit_log_entry, request_handler)
        entity_regex = re.search(
                "^([a-z]+\\:[a-z\\.\\-]+) \\(([A-Z0-9\\-\\_]+)\\)\\:",
                str(audit_log_entry['entityId'])
        )
        entity_id = entity_regex.group(2)
        entity_type = entity_regex.group(1)
        annotation_data ['entityId'] = f"\"{entity_id}\""
        annotation_data ['properties']['entityType'] = entity_type
        if entity_id.startswith("PROCESS_GROUP-"):
            pgi_list = self.get_processes_from_group(entity_id, request_handler)
            pgi_str = self.process_group_instance_to_entity_str(pgi_list)
            annotation_data ['entityId'] = pgi_str
        return annotation_data
