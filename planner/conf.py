# === RECOMMENDED ALTERNATIVE PORTS ===
# For each standard port, an alternative higher port is suggested
ALTERNATIVE_PORTS = {
    80: 8080,      # HTTP: from 80 to 8080
    21: 2121,      # FTP: from 21 to 2121
    23: 2323,      # Telnet: from 23 to 2323
    110: 1110,     # POP3: from 110 to 1110
    143: 1143,     # IMAP: from 143 to 1143
    3389: 33389,   # RDP: from 3389 to 33389
    5900: 59000,   # VNC: from 5900 to 59000
    445: 4455,     # SMB: from 445 to 4455
    389: 3890,     # LDAP: from 389 to 3890
    2049: 20490,   # NFS: from 2049 to 20490
    5432: 54320,   # PostgreSQL: from 5432 to 54320
    8080: 80800,   # Tomcat: from 8080 to 80800
}


# === MITIGATION ACTION COSTS ===
# Assigns a cost to each mitigation action to aid in strategy evaluation
ACTION_COSTS = {
    'close_port': 1,       # Low cost: simple operation, no impact
    'disable_service': 5,  # High cost: causes service downtime!
    'migrate_service': 3   # Medium cost: requires reconfiguration but no downtime
}