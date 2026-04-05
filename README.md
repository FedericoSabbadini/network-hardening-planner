# Network Hardening Planner

[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Unified Planning](https://img.shields.io/badge/Unified%20Planning-Framework-orange.svg)](https://unified-planning.readthedocs.io/)
[![Fast Downward](https://img.shields.io/badge/Solver-Fast%20Downward-purple.svg)](https://www.fast-downward.org/)

**Automated Planning system for network infrastructure security hardening.**

---

## Overview

Enterprise network infrastructures often expose insecure or legacy services — HTTP on port 80, Telnet on port 23, FTP on port 21 — that violate modern security policies. Closing or remediating these is non-trivial: active services may depend on each other, some are business-critical, and the order of operations matters.

**Network Hardening Planner** treats this as a **Classical Planning** problem. Given a JSON description of a network (hosts, services, ports, vulnerabilities, dependencies) and a security policy (forbidden ports, forbidden services), it uses the [Unified Planning Framework](https://unified-planning.readthedocs.io/) and the [Fast Downward](https://www.fast-downward.org/) solver to produce a **minimum-cost, goal-satisfying action plan**.

---

## Project Structure

```
network-hardening-planner/
├── main.py                        # Entry point: runs scenarios, collects metrics, plots charts
├── planner/
│   ├── domain.py                  # Planning domain: types, fluents, actions
│   ├── problem.py                 # Problem instantiation, initial state, goals, solver
│   └── conf.py                    # Configuration: action costs, alternative ports
├── input/
│   ├── scenarios/                 # Benchmark scenarios (01–08)
│   │   ├── 01_all_actions_basic.json
│   │   ├── 02_deps_all_actions.json
│   │   ├── 03_enterprise_mixed.json
│   │   ├── 04_security_incident.json
│   │   ├── 05_healthcare_gdpr.json
│   │   ├── 06_financial_pci.json
│   │   ├── 07_stress_test.json
│   │   └── 08_impossible.json
│   └── use_cases/                 # Realistic use-case scenarios (09–11)
│       ├── 09_devops_pipeline.json
│       ├── 10_ecommerce_platform.json
│       └── 11_telecom_core.json
└── output/                        # Generated plans, CSVs, and charts (created at runtime)
```

---

## How It Works

The problem is modelled as a **Classical Planning** instance with three object types, twelve fluents, and seven actions.

### Types

| Type | Description |
|---|---|
| `Host` | A machine in the network (server, workstation, appliance) |
| `Port` | A TCP/UDP port number |
| `Service` | A running service bound to one or more ports |

### Fluents (State Predicates)

| Fluent | Signature | Meaning |
|---|---|---|
| `open_port` | (Host, Port) | Port is currently open on the host |
| `service_active` | (Host, Service) | Service is currently running |
| `service_critical` | (Host, Service) | Service cannot be disabled without unacceptable impact |
| `service_uses_port` | (Host, Service, Port) | Service is actively bound to this port |
| `service_used_port` | (Host, Service, Port) | Port was previously used by the service (for restore) |
| `depends_on` | (Host, Service, Host, Service) | First service depends on availability of second |
| `migrate_possibility` | (Host, Service, Port, Port) | Service can be moved from old port to new port |
| `open_possibility` | (Host, Port) | A safe, non-forbidden port is available to open |
| `service_vulnerable` | (Host, Service) | Service has an unmitigated vulnerability |
| `port_forbidden` | (Port) | Port is banned by security policy |
| `service_forbidden` | (Service) | Service is banned by security policy |
| `service_reachable` | (Host, Service) | Service is accessible from outside the network |

### Actions

| Action | Cost | Preconditions (key) | Effects |
|---|---|---|---|
| `patch_service` | 3 | service active, vulnerable, not reachable | sets `service_vulnerable = False` |
| `block_for_maintenance` | 4 | service active, reachable, vulnerable, uses port | closes port, stores used port, makes service unreachable |
| `restore_service` | 4 | service active, not reachable, not vulnerable, port was used | reopens port, makes service reachable again |
| `block_port` | 5 | port open, no reachable dependents | closes port, makes service unreachable |
| `disable_service` | 10 | service active, not reachable, not critical | deactivates service entirely |
| `open_new_port` | 14 | service active, port available, not forbidden | opens port, makes service reachable |
| `migrate_service` | 16 | migration possible, service not critical, not forbidden | moves service to new port |

### Goal Structure

The planner is asked to satisfy five types of goals simultaneously:

- **G1** — All vulnerable, non-forbidden services must be patched (`¬service_vulnerable`)
- **G2** — All forbidden ports must be closed (`¬open_port`)
- **G3** — All forbidden services must be disabled (`¬service_active`)
- **G4** — All non-forbidden services must remain reachable (`service_reachable`)
- **G5** — Vulnerable services on permitted ports must keep using those ports (no unnecessary migration)

The quality metric is **MinimizeActionCosts** — Fast Downward finds the minimum-cost plan satisfying all goals.

---

## Input Format

Each scenario is a JSON file with the following structure:

```json
{
  "scenario_name": "example",
  "description": "Human-readable description",
  "hosts": [
    {
      "id": "webserver",
      "features": [
        {
          "service": "http",
          "port": 80,
          "critical": false,
          "vulnerable": false,
          "depends_on_service": []
        }
      ]
    }
  ],
  "policy": {
    "forbidden_ports": [80, 23, 21],
    "forbidden_services": ["telnet", "ftp"]
  }
}
```

### Feature Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `service` | string | yes | Service identifier (e.g., `"http"`, `"ssh"`) |
| `port` | int or null | yes | Port number; `null` = internal-only service |
| `critical` | bool | no | If `true`, service cannot be disabled or migrated |
| `vulnerable` | bool | no | If `true`, service has an unmitigated CVE |
| `depends_on_service` | list | no | List of `{"host": ..., "service": ...}` dependencies |

---

## Setup & Usage

### Requirements

```
unified-planning
up-fast-downward
pandas
matplotlib
numpy
```

### Installation

```bash
pip install unified-planning up-fast-downward pandas matplotlib numpy
```

### Run

```bash
python main.py
# Enter folder name when prompted: scenarios  (or  use_cases)
```

Plans are saved to `output/<folder>/plans/`, a summary CSV to `output/<folder>/summary.csv`, and charts to `output/<folder>/`.

---

## Scenario Catalogue

### Benchmark Scenarios (`input/scenarios/`)

| # | Name | Hosts | Description |
|---|---|---|---|
| 01 | `all_actions_basic` | 3 | All action types exercised; baseline test |
| 02 | `deps_all_actions` | 4 | Service dependency chains |
| 03 | `enterprise_mixed` | 8 | Mixed criticality; 5 forbidden ports |
| 04 | `security_incident` | 6 | Post-breach emergency hardening |
| 05 | `healthcare_gdpr` | 7 | GDPR compliance profile |
| 06 | `financial_pci` | 9 | PCI-DSS compliance; 7 forbidden ports/services |
| 07 | `stress_test` | 14 | Scalability and solver performance |
| 08 | `impossible` | 1 | Critical service on a forbidden port — no valid plan exists |

### Use Cases (`input/use_cases/`)

| # | Name | Description |
|---|---|---|
| 09 | `devops_pipeline` | CI/CD infrastructure hardening |
| 10 | `ecommerce_platform` | Mixed public/private e-commerce stack |
| 11 | `telecom_core` | Core telecom network with legacy protocols |

---

## Key Design Decisions

**Classical Planning over other formalisms.** The problem has a finite, fully observable state space with deterministic actions and clear goal conditions — the ideal fit for classical planning. This guarantees that if a plan exists, Fast Downward finds the optimal one.

**Action cost model.** Costs encode operational impact (service downtime) plus execution risk. `migrate_service` (16) and `open_new_port` (14) are the most expensive because they require coordinated downtime and carry compatibility risk. `patch_service` (3) and `restore_service` (4) are the cheapest — they are additive to security without disrupting availability.

**`service_reachable` as an intermediate fluent.** Rather than encoding network reachability structurally, it is tracked as a fluent. This allows the planner to reason about it directly in preconditions and effects, enabling the dependency logic in `block_port` without requiring complex axioms.

**`service_used_port` as history tracking.** The `block_for_maintenance → patch → restore_service` sequence needs to remember which port a service was using before it was blocked. The auxiliary fluent `service_used_port` acts as this memory, allowing `restore_service` to re-open the correct port.

**Universal precondition on `block_port`.** Before a port can be blocked, all services that depend on it must already be unreachable. This is enforced with a `Forall/Implies` universal quantification, preventing the planner from generating plans that leave dependent services broken.

**Grounding before solving.** Fast Downward operates on propositional (ground) problems. The Unified Planning `Compiler` with `CompilationKind.GROUNDING` lifts the typed first-order problem to ground STRIPS, and `map_back_action_instance` translates the resulting plan back to readable typed action calls.

**Global policy, local state.** Forbidden ports and forbidden services are global (policy-level) fluents, not per-host. This models real security policy correctly: if `telnet` is forbidden, it is forbidden everywhere, not just on one host.

---

## License

MIT License — see [LICENSE](LICENSE) for details.
