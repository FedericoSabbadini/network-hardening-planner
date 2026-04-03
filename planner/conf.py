# === MITIGATION ACTION COSTS ===
# Criteria: operational impact (downtime) + risk during the operation
ACTION_COSTS = {
    'block_port': 5,  # makes the service that depends on it unavailable from outside
    'patch_service':        7,  # may require downtime to apply the patch, and there is a risk the patch may cause unexpected service issues (e.g., incompatibility, bugs, etc.)
    'migrate_service':      16,   # may require downtime to migrate the service to a new port, and there is a risk the migration may cause unexpected service issues (e.g., incompatibility, bugs, etc.)
    'disable_service':    10 ,  # makes the service completely unavailable, with lower operational impact than blocking the port, but with lower risk during operation (it is simpler to disable a service than to migrate or patch it)
    'reuse_service':       14,   # may require downtime to open the port and let the service use it, and there is a risk opening the port may cause unexpected service issues (e.g., incompatibility, bugs, etc.)
    'turnoff_safely': 12,  # similar to disable_service, but for vulnerable services
    'patch_with_attention': 10,  # similar to patch_service, but for critical services, which may require more careful testing and validation before applying the patch, and may have a higher risk of causing unexpected service issues (e.g., incompatibility, bugs, etc.)
}

# === ALTERNATIVE PORTS ===
ALTERNATIVE_PORTS = {
    80:   8080, # http -> http-alt
    21:   2121, # ftp -> ftp-alt
    23:   2323, # telnet -> telnet-alt
    110:  1110, # pop3 -> pop3-alt
    143:  1143, # imap -> imap-alt
    3389: 33389, # rdp -> rdp-alt
    5900: 59000, # vnc -> vnc-alt
    445:  4455, # smb -> smb-alt
}

# === SERVICE PORTS === usable to open services of various types / free ports
SERVICE_PORTS = [9000, 9001, 9002, 9003, 9004, 9005, 9006, 9007, 9008, 9009]