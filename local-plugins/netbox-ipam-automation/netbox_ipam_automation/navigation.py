from netbox.plugins import PluginMenu, PluginMenuButton, PluginMenuItem


menu = PluginMenu(
    label="IPAM Automation",
    icon_class="mdi mdi-radar",
    groups=(
        (
            "Automation",
            (
                PluginMenuItem(
                    link="plugins:netbox_ipam_automation:globalsettings_list",
                    link_text="Global Settings",
                    permissions=["netbox_ipam_automation.view_globalsettings"],
                    buttons=(
                        PluginMenuButton(
                            link="plugins:netbox_ipam_automation:globalsettings_add",
                            title="Add",
                            icon_class="mdi mdi-plus-thick",
                            permissions=["netbox_ipam_automation.add_globalsettings"],
                        ),
                    ),
                ),
                PluginMenuItem(
                    link="plugins:netbox_ipam_automation:rangepolicy_list",
                    link_text="Range Policies",
                    permissions=["netbox_ipam_automation.view_rangepolicy"],
                    buttons=(
                        PluginMenuButton(
                            link="plugins:netbox_ipam_automation:rangepolicy_add",
                            title="Add",
                            icon_class="mdi mdi-plus-thick",
                            permissions=["netbox_ipam_automation.add_rangepolicy"],
                        ),
                    ),
                ),
                PluginMenuItem(
                    link="plugins:netbox_ipam_automation:scanrun_list",
                    link_text="Scan Runs",
                    permissions=["netbox_ipam_automation.view_scanrun"],
                    buttons=(
                        PluginMenuButton(
                            link="plugins:netbox_ipam_automation:scanrun_add",
                            title="Add",
                            icon_class="mdi mdi-plus-thick",
                            permissions=["netbox_ipam_automation.add_scanrun"],
                        ),
                    ),
                ),
            ),
        ),
    ),
)
