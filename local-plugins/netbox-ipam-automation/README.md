# netbox-ipam-automation

Local NetBox 4.6 plugin for IPAM scan policy automation.

What is here:
- Python package: `netbox_ipam_automation`
- Plugin config and packaging metadata
- Models for global settings, range policies, and scan runs
- Range policies require a complete IPv4 NetBox IP range and may scan a bounded subrange
- Slugs are generated from policy names
- Per-policy interval or multi-expression cron scheduling with global inheritance
- Confirmed HITL initialization for reserved network/broadcast addresses and a gateway
- NetBox UI plumbing: forms, tables, filtersets, views, navigation
- REST API serializers/viewsets/router
- NetBox system-job scheduling and scan-result classification

What is not here:
- No raw network scanning
- Scan execution still uses the safe stub adapter

Version compatibility is enforced by `PluginConfig`, not by a PyPI `netbox`
dependency, because this plugin is installed into the NetBox Docker image.
