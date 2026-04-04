# === MITIGATION ACTION COSTS ===
# Criteria: operational impact (downtime) + risk during the operation
ACTION_COSTS = {
    'block_for_maintenance': 4, # temporary block for maintenance, which can be done during off-peak hours and has a lower risk compared to other actions
    'block_port':            5, # blocking a port, which can cause service disruption and may require firewall or network configuration changes, but is generally less risky than disabling or migrating services
    'patch_service':         3, # patching a service, which can be done with minimal downtime if planned properly, and can significantly reduce the risk of exploitation, but may require testing and validation to ensure compatibility and stability
    'migrate_service':       16, # migrating a service to a different port or server, which can involve significant downtime, configuration changes, and potential compatibility issues, and may require coordination with other teams and stakeholders
    'disable_service':       10, # disabling a service, which can cause significant disruption and may require manual intervention to restore, but can be necessary for critical vulnerabilities or when no other mitigation options are available
    'open_new_port':         14, # opening a new port for a service, which can involve configuration changes and potential security risks if not done properly, but can be necessary for services that need to be reused or for new deployments
    'restore_service':       4, # restoring a service after mitigation, which can involve some downtime and potential issues if not done carefully, but is necessary to return to normal operations and can be planned to minimize impact
}

# === ALTERNATIVE PORTS ===
# Criteria: commonly used alternative ports for the same services, which are often used for testing, development, or alternative deployments, and are less likely to be blocked by firewalls or network policies, but may require some configuration changes to use them
ALTERNATIVE_PORTS = {
    80:   80808, # http -> http-alt
    21:   2121, # ftp -> ftp-alt
    143:  1143, # imap -> imap-alt
    3389: 33389, # rdp -> rdp-alt
    5900: 59000, # vnc -> vnc-alt
}

# === SERVICE PORTS === 
# Criteria: ports that are commonly used by services and are available for deployment, which can be used for migrating services to alternative ports or for opening new ports for services that need to be reused
SERVICE_PORTS = [9000, 9001, 9002, 9003, 9004, 9005, 9006, 9007, 9008, 9009]