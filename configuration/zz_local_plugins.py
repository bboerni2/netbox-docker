import os


def _enabled(name: str) -> bool:
    return os.getenv(name, "").lower() in {"1", "true", "yes", "on"}


diode_target = os.getenv("DIODE_GRPC_TARGET")
diode_secret = os.getenv("NETBOX_TO_DIODE_CLIENT_SECRET")

PLUGINS = [
    "netbox_ipam_automation",
    "netbox_topology_views",
    "netbox_lifecycle",
    "netbox_floorplan",
    "netbox_lists",
    "netbox_inventory",
    "netbox_reorder_rack",
    "netbox_initializers",
    "netbox_bgp",
    "netbox_dns",
]

if _enabled("ENABLE_DIODE") and diode_target and diode_secret:
    PLUGINS.append("netbox_diode_plugin")

PLUGINS_CONFIG = {
    "netbox_inventory": {
        "sync_serial_to_device": True,
        "sync_asset_tag_to_device": True,
    },
    "netbox_bgp": {
        "top_level_menu": True,
    },
    "netbox_dns": {},
}

if _enabled("ENABLE_DIODE") and diode_target and diode_secret:
    PLUGINS_CONFIG["netbox_diode_plugin"] = {
        "diode_target_override": diode_target,
        "diode_username": os.getenv("DIODE_USERNAME", "diode"),
        "netbox_to_diode_client_secret": diode_secret,
        "auth": {
            "issuer": diode_target.replace("grpc://", "http://") + "/auth",
        },
    }
