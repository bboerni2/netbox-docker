from netbox.plugins import PluginConfig

from .version import __version__


class NetBoxIPAMAutomationConfig(PluginConfig):
    name = "netbox_ipam_automation"
    verbose_name = "NetBox IPAM Automation"
    description = "Minimal IPAM automation skeleton for NetBox"
    version = __version__
    author = "OpenAI Codex"
    author_email = "noreply@example.invalid"
    base_url = "ipam-automation"
    min_version = "4.6.0"
    max_version = "4.6.99"
    default_settings = {
        "stub_mode": True,
    }
    required_settings = []


config = NetBoxIPAMAutomationConfig
