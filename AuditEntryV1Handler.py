from re import U
from AuditEntryBaseHandler import AuditEntryBaseHandler
import logging

class AuditEntryV1Handler(AuditEntryBaseHandler):
    def extract_info(self, audit_log_entry):
        eventType = str(audit_log_entry['eventType'])
        user = str(audit_log_entry['user'])
        category = str(audit_log_entry['category'])
        timestamp = int(audit_log_entry['timestamp'])
        entityId = str(audit_log_entry['entityId']).rsplit(maxsplit=1)[1]
        entityType = str(audit_log_entry['entityId']).split(maxsplit=1)[0]
        patch = str(audit_log_entry['patch'])
        results = {
            'entityId' : entityId,
            'properties' : {
              "eventType" : eventType,
              "user" : user,
              "category" : category,
              "timestamp": timestamp,
              "patch" : patch,
            }
        }
        # If entityId beings with ME_ then proceed to extract the real entityId by replacing the match with nothing
        if entityType.startswith("ME_PROCESS_GROUP:") and user != "agent quotas worker":
            pgi_list = self.get_processes_from_group(entityId)
            results ['entityId'] = pgi_list
        elif entityType.startswith("ME_") and user != "agent quotas worker":
            return results
        else:
            logging.info(
                f"AUDIT - NOT MATCHED: {user} {eventType} {category} {timestamp} {entityId}")

