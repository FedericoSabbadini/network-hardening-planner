# === SERVICE AND PORT CONFIGURATION ===
# Mapping of services to their standard port numbers
SERVICE_PORT_MAPPING = {
    # Web services
    'http': [80],           # Unencrypted HTTP (insecure)
    'https': [443],         # Encrypted HTTP (secure)
    'ssh': [22],            # Secure Shell (secure)

    # Database
    'mysql': [3306],        # MySQL
    'postgresql': [5432],   # PostgreSQL
    'redis': [6379],        # Redis (cache)
    'mongodb': [27017],     # MongoDB

    # Legacy protocols (generally insecure)
    'ftp': [21],            # File Transfer Protocol
    'telnet': [23],         # Unencrypted remote terminal
    'smtp': [25],           # Email (basic version)
    'pop3': [110],          # Email retrieval
    'imap': [143],          # Email retrieval

    # Application server
    'tomcat': [8080],       # Java application server
    'nodejs': [3000],       # Node.js default port
    'rabbitmq': [5672],     # Message queue

    # Monitoring
    'prometheus': [9090],   # Metrics collection
    'grafana': [3000],      # Dashboard
    'elasticsearch': [9200], # Search engine
    'kibana': [5601],       # Log visualization

    # File sharing and remote access
    'smb': [445],           # Windows file sharing
    'netbios': [139],       # Legacy Windows networking
    'rdp': [3389],          # Remote Desktop
    'vnc': [5900],          # Virtual Network Computing
    'nfs': [2049],          # Network File System
    'ldap': [389],          # Directory service

    # Utility
    'rsync': [873],         # File synchronization
    'snmp': [161],          # Network management (insecure)
    'tftp': [69],           # Trivial FTP (very insecure)
    'dns': [53],            # Domain Name System
    
    
    # Other common services
    'dhcp': [67],           # Dynamic Host Configuration Protocol
    'ntp': [123],           # Network Time Protocol
    'sip': [5060],          # Session Initiation Protocol (VoIP)
    'rtsp': [554],          # Real Time Streaming Protocol
    'ldap': [389],          # Lightweight Directory Access Protocol
    'kerberos': [88],       # Kerberos authentication
    'syslog': [514],        # System logging
    'snmp': [161],          # Simple Network Management Protocol
    'sftp': [22],           # Secure File Transfer Protocol (over SSH)
    'pop3': [110],          # Post Office Protocol 3
    'ntp': [123],           # Network Time Protocol

}


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
    3306: 33060,   # MySQL: from 3306 to 33060
    5432: 54320,   # PostgreSQL: from 5432 to 54320
    8080: 80800,   # Tomcat: from 8080 to 80800
}


# === MITIGATION ACTION COSTS ===
# Assigns a cost to each mitigation action to aid in strategy evaluation
ACTION_COSTS = {
    'close_port': 1,       # Low cost: simple operation, no impact
    'deactivate_service': 5, # High cost: causes service downtime!
    'migrate_service': 3      # Medium cost: requires reconfiguration but no downtime
}