# === CONFIGURAZIONE DEI SERVIZI E PORTE ===
# Mappa dei servizi ai loro numeri di porta standard
SERVICE_PORT_MAPPING = {
    # Servizi web
    'http': [80],           # HTTP non cifrato (insicuro)
    'https': [443],         # HTTP cifrato (sicuro)
    'ssh': [22],            # Secure Shell (sicuro)

    # Database
    'mysql': [3306],        # MySQL
    'postgresql': [5432],   # PostgreSQL
    'redis': [6379],        # Redis (cache)
    'mongodb': [27017],     # MongoDB

    # Protocolli legacy (generalmente insicuri)
    'ftp': [21],            # File Transfer Protocol
    'telnet': [23],         # Terminale remoto non cifrato
    'smtp': [25],           # Email (versione base)
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

    # File sharing e accesso remoto
    'smb': [445],           # Windows file sharing
    'netbios': [139],       # Legacy Windows networking
    'rdp': [3389],          # Remote Desktop
    'vnc': [5900],          # Virtual Network Computing
    'nfs': [2049],          # Network File System
    'ldap': [389],          # Directory service

    # Utility
    'rsync': [873],         # File synchronization
    'snmp': [161],          # Network management (insicuro)
    'tftp': [69],           # Trivial FTP (molto insicuro)
}


# === PORTE ALTERNATIVE CONSIGLIATE ===
# Per ogni porta standard, viene suggerita una porta alternativa più alta
ALTERNATIVE_PORTS = {
    80: 8080,      # HTTP: da 80 a 8080
    21: 2121,      # FTP: da 21 a 2121
    23: 2323,      # Telnet: da 23 a 2323
    110: 1110,     # POP3: da 110 a 1110
    143: 1143,     # IMAP: da 143 a 1143
    3389: 33389,   # RDP: da 3389 a 33389
    5900: 59000,   # VNC: da 5900 a 59000
    445: 4455,     # SMB: da 445 a 4455
    389: 3890,     # LDAP: da 389 a 3890
    2049: 20490,   # NFS: da 2049 a 20490

    # NOTA: Le seguenti porte NON hanno alternativa!
    # Questo significa che i servizi su queste porte devono essere DISATTIVATI
    # - 25 (SMTP): protocollo email legacy
    # - 139 (NetBIOS): protocollo Windows obsoleto
    # - 161 (SNMP): management non sicuro
    # - 69 (TFTP): trasferimento file senza autenticazione
}


# === COSTI DELLE AZIONI DI MITIGAZIONE ===
# Assegna un costo a ciascuna azione di mitigazione per aiutare nella valutazione delle strategie
ACTION_COSTS = {
    'chiudi_porta': 1,       # Costo basso: operazione semplice, nessun impatto
    'disattiva_servizio': 5, # Costo alto: causa downtime del servizio!
    'migra_servizio': 3      # Costo medio: richiede riconfigurazione ma no downtime
}