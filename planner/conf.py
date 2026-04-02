# === MITIGATION ACTION COSTS ===
# Criteri: impatto operativo (downtime) + rischio durante l'operazione
ACTION_COSTS = {
    'block_port_firewall': 10,  # rende il servizio che si basa su essa indisponibile dall'esterno 
    'patch_service':        4,  # può richiedere un downtime per applicare la patch, e c'è il rischio che la patch causi problemi imprevisti al servizio (es. incompatibilità, bug, ecc.)
    'migrate_service':      8,   # può richiedere un downtime per migrare il servizio su una nuova porta, e c'è il rischio che la migrazione causi problemi imprevisti al servizio (es. incompatibilità, bug, ecc.)
    'disable_service':    5 ,  # rende il servizio indisponibile completamente, con impatto operativo minore rispetto a bloccare la porta, ma con rischio minore durante l'operazione (è più semplice disabilitare un servizio che migrare o patchare)
    'reuse_service':       20,   # può richiedere un downtime per aprire la porta e farla usare dal servizio, e c'è il rischio che l'apertura della porta causi problemi imprevisti al servizio (es. incompatibilità, bug, ecc.)
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

# === SERVICE PORTS === usable to open services of various type / free ports
SERVICE_PORTS = [9000, 9001, 9002, 9003, 9004, 9005, 9006, 9007, 9008, 9009]