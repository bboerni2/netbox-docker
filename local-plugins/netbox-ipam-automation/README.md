# netbox-ipam-automation

Minimal local NetBox 4.6 plugin skeleton for IPAM automation.

What is here:
- Python package: `netbox_ipam_automation`
- Plugin config and packaging metadata
- Models for global settings, range policies, and scan runs
- Range policies can point at NetBox IPAM ranges or a CIDR override
- Cron expressions are stored as newline-separated values for later scheduler work
- NetBox UI plumbing: forms, tables, filtersets, views, navigation
- REST API serializers/viewsets/router
- Safe stub logic for scheduling and scan classification

What is not here:
- No raw network scanning
- No background worker integration beyond placeholders

Version compatibility is enforced by `PluginConfig`, not by a PyPI `netbox`
dependency, because this plugin is installed into the NetBox Docker image.
