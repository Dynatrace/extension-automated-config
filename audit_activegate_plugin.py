from ruxit.api.base_plugin import RemoteBasePlugin
from audit_logging import run_audit
import logging

logger = logging.getLogger(__name__)


class AuditPluginRemote(RemoteBasePlugin):
    pollCount = 1
    
    def initialize(self, **kwargs):
        logger.info("Config: %s", self.config)
        self.url = ""

    def query(self, **kwargs):
        # Create group - provide group id used to calculate unique entity id in dynatrace
        #   and display name for UI presentation
        # group = self.results_builder.report_custom_annotation_event()
        config = kwargs['config']
        domain = config['domain'].strip()
        tenant = config['tenant'].strip()
        apiToken = config['apiToken'].strip()
        pollingInterval = config['pollingInterval']

        if self.pollCount < pollingInterval:
            self.pollCount += 1
            return
        self.pollCount = 1
        run_audit(domain, tenant, apiToken, pollingInterval)