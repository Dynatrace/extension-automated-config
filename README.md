# dt-automated-config-audit 📝
With multiple Dyantrace admins managing a tenant, It can often be difficult to track accountability of Dynatrace configuration changes. The Dynatrace Automated Configuration Audit uses the flexible Dynatrace API to report configuration changes made to Dynatrace Entities and reports it into the Event feed of the entity altered. This allows for a clear visalization and accountability of changes to you Applications, Services, Processes and Hosts. This is an ActiveGate extension that only needs to sit on 1 Dynatrace ActiveGate to operate.

## Prerequisites ✔️
1) Enable *"Log all audit-related system events"* in your Dynatrace environment
> - Go to Settings -> Preferences -> Data privacy and security -> Log audit events
2) Create API Token with auditLogs.read, entities.read and events.ingest permissiones
    NOTE: In future versions more permissions will be required, including ReadConfig and DataExport

## Installation 🚀
1) Download the <a href="https://github.com/geoteo/dt-automated-config-audit/releases" target="_blank">latest release.</a>
2) Upload extension to ActiveGate.
> - Linux: /opt/dynatrace/remotepluginmodule/plugin_deployment
> - Windows: C:\Program Files\dynatrace\remotepluginmodule\plugin_deployment
3) Upload extension to the Dynatrace Server via the Dynatrace web UI.
> - Go to Settings -> Monitored technologies -> Custom extensions -> Upload extension
4) Configure Extension Settings for your environment.

## Screenshot 📸
![Screenshot](https://github.com/geoteo/dt-automated-config-audit/blob/master/Automated%20Configuration%20Audit.png)

## Development ⌨️
- An optimal development environment should use Python 3.8 and pipenv
- Dependencies needed are requests, pytz and a current plugin-sdk available from your Dynatrace environment

## Contact 🤝
Created by George Teodorescu and Aaron Philipose - feel free to contact us!
