# 🔐 Network Hardening Planner

[![Jupyter Notebook](https://img.shields.io/badge/Jupyter-Notebook-orange.svg)](https://jupyter.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**Sistema di pianificazione automatica per la messa in sicurezza di infrastrutture di rete.**

## Idea del Progetto

Le infrastrutture di rete aziendali spesso presentano porte aperte considerate insicure dalle policy di sicurezza moderne: HTTP non cifrato (porta 80), Telnet (porta 23), FTP (porta 21), e altri protocolli legacy.

Chiudere queste porte non è un'operazione banale perché:
- Servizi attivi potrebbero dipendere da esse
- Alcuni servizi sono critici per il business
- Le dipendenze tra componenti rendono complessa la sequenza di operazioni

**Network Hardening Planner** risolve questo problema utilizzando tecniche di Intelligenza Artificiale, specificamente **Automated Planning**.

## Come Funziona

Il problema è formalizzato come un problema di **Classical Planning**:

```
STATO INIZIALE                        GOAL
┌─────────────────────┐              ┌─────────────────────┐
│ Host: webserver     │              │                     │
│ Porte: 80, 443, 22  │    ====>     │ Porta 80: CHIUSA    │
│ Servizi: http, ssh  │   PLANNER    │ Porta 23: CHIUSA    │
│                     │              │ (su tutti gli host) │
│ Host: database      │              │                     │
│ Porte: 3306, 23     │              │                     │
└─────────────────────┘              └─────────────────────┘
```

Il planner (Fast-Downward) esplora lo spazio degli stati e trova la sequenza di azioni a costo minimo.

## Azioni Disponibili

| Azione | Costo | Quando si usa |
|--------|-------|---------------|
| `chiudi_porta` | 1 | Porta senza servizi attivi |
| `disattiva_servizio` | 5 | Servizio non critico da fermare |
| `migra_servizio` | 3 | Spostare servizio su porta alternativa |

**Esempio di piano generato:**
```
1. migra_servizio(webserver, http, 80 → 8080)
2. disattiva_servizio(mailserver, smtp)
3. chiudi_porta(mailserver, 25)
4. chiudi_porta(database, 23)
```

## Quick Start

### Google Colab (consigliato)
1. Carica `network_hardening.ipynb` su Colab
2. Esegui tutte le celle

### Locale
```bash
pip install unified-planning up-fast-downward pandas matplotlib
jupyter notebook network_hardening.ipynb
```

## Struttura del Progetto

```
network_hardening/
├── network_hardening.ipynb   # Notebook principale
├── DOCUMENTATION.md          # Documentazione completa
├── README.md
├── scenarios/                # Scenari di test (generati)
└── results/                  # Risultati (generati)
```

## Scenari di Test

| Scenario | Descrizione | Complessità |
|----------|-------------|-------------|
| Basic | Tutte le azioni | 3 host |
| Dependencies | Dipendenze tra servizi | 4 host |
| Enterprise | Infrastruttura aziendale | 8 host |
| Security Incident | Post-breach hardening | 6 host |
| Healthcare | Compliance GDPR | 7 host |
| Financial | Compliance PCI-DSS | 9 host |
| Stress Test | Scalabilità | 14 host |

## Tecnologie

- **Unified Planning**: framework Python per automated planning
- **Fast-Downward**: solver state-of-the-art per planning classico
- **Python 3.8+**

## License

MIT License — See [LICENSE](LICENSE) for details.
