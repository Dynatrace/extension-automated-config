# dt-automated-config-audit 📝
> Dynatrace ActiveGate Extension to automatically flow Dynatrace configuration changes directly into the UI for Applications, Hosts, Services, and Processes.

## Prerequisites ✔️
1) Enable *"Log all audit-related system events"* in your Dynatrace environment
> - Go to Settings -> Preferences -> Data privacy and security -> Log audit events
2) Create API Token with V1 metrics, Audit Logs & Read Entities

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

## Contact 🤝
Created by George Teodorescu and Aaron Philipose - feel free to contact us!

## License 🧾

[![License](http://img.shields.io/:license-mit-blue.svg?style=flat-square)](http://badges.mit-license.org)
- **[MIT license](http://opensource.org/licenses/mit-license.php)**
