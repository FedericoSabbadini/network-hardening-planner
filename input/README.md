# Input File Format Guide

This document explains how to write a valid JSON input file for the **Network Hardening Planner**.

---

## File Location

Place your JSON file in one of the two input folders:

- `input/scenarios/` — for benchmark or test scenarios
- `input/use_cases/` — for realistic, production-like scenarios

The filename should follow the existing naming convention: `NN_short_description.json` (e.g., `12_my_network.json`).

---

## Top-Level Structure

Every input file must have exactly three top-level keys:

```json
{
  "scenario_name": "string",
  "description": "string",
  "hosts": [ ... ],
  "policy": { ... }
}
```

| Field           | Type   | Required | Description                                              |
|-----------------|--------|----------|----------------------------------------------------------|
| `scenario_name` | string | yes      | Short unique identifier, typically matching the filename |
| `description`   | string | yes      | Human-readable summary of the scenario                   |
| `hosts`         | array  | yes      | List of host objects (see below)                         |
| `policy`        | object | yes      | Security policy: forbidden ports and services            |

---

## Hosts

The `hosts` array contains one object per machine in your network.

```json
{
  "id": "webserver",
  "features": [ ... ]
}
```

| Field      | Type   | Required | Description                            |
|------------|--------|----------|----------------------------------------|
| `id`       | string | yes      | Unique identifier for this host        |
| `features` | array  | yes      | List of services running on this host  |

### Host IDs

- Must be **unique** across the entire file.
- Use lowercase with underscores: `web_frontend1`, `user_db_master`.
- Avoid spaces or special characters.

---

## Features (Services)

Each entry in `features` describes one service running on the host.

```json
{
  "service": "http",
  "port": 80,
  "critical": false,
  "vulnerable": true,
  "depends_on_service": [
    {
      "host": "api_gateway",
      "service": "nodejs"
    }
  ]
}
```

### Feature Fields

| Field               | Type        | Required | Default | Description                                                                 |
|---------------------|-------------|----------|---------|-----------------------------------------------------------------------------|
| `service`           | string      | **yes**  | —       | Service identifier (e.g., `"http"`, `"ssh"`, `"postgresql"`)                |
| `port`              | int or null | **yes**  | —       | TCP/UDP port the service listens on; use `null` for internal-only services  |
| `critical`          | bool        | no       | `false` | If `true`, the service cannot be disabled or migrated by the planner        |
| `vulnerable`        | bool        | no       | `false` | If `true`, the service has an unmitigated vulnerability and must be patched |
| `depends_on_service`| array       | no       | `[]`    | Other services this service requires to be reachable                        |

### `depends_on_service` entries

Each dependency is an object with two fields:

| Field     | Type   | Required | Description                                      |
|-----------|--------|----------|--------------------------------------------------|
| `host`    | string | yes      | The `id` of the host running the required service|
| `service` | string | yes      | The service identifier on that host              |

> **Important:** Both `host` and `service` must match values that actually exist elsewhere in the file. A typo here will produce an invalid planning problem.

---

## Policy

The `policy` object defines what the security policy forbids. The planner will generate a plan to satisfy these constraints.

```json
{
  "policy": {
    "forbidden_ports": [80, 21, 23, 139, 161, 3389, 5900, 445],
    "forbidden_services": ["ftp", "telnet", "snmp", "rdp", "vnc"]
  }
}
```

| Field               | Type          | Required | Description                                          |
|---------------------|---------------|----------|------------------------------------------------------|
| `forbidden_ports`   | array of int  | yes      | Port numbers that must be closed in the final state  |
| `forbidden_services`| array of string| yes     | Service names that must not be active in final state |

> **Note:** The policy is **global** — if a port or service is forbidden, it is forbidden on every host. There is no per-host policy override.

---

## Validation Rules

Before running the planner, verify that your file respects these rules:

1. **All host `id` values are unique.**
2. **Every `depends_on_service` reference points to an existing `host` + `service` pair.**
3. **A service marked `critical: true` should not also be on a `forbidden_port` or listed in `forbidden_services`** — this creates an unsolvable problem (the planner cannot disable a critical service). See `08_impossible.json` for an example of this edge case.
4. **Each host has at least one service** — hosts with an empty `features` array serve no purpose in the model.
5. **Port numbers are integers**, not strings. Use `80`, not `"80"`.
6. **Boolean fields are JSON booleans**: `true` / `false`, not `"true"` / `"false"`.

---

## Common Service Identifiers

The planner treats service names as opaque strings, but using consistent names across your files makes scenarios more readable and comparable.

| Protocol     | Suggested identifier  | Default port |
|--------------|-----------------------|--------------|
| HTTP         | `http`                | 80           |
| HTTPS        | `https`               | 443          |
| SSH          | `ssh`                 | 22           |
| FTP          | `ftp`                 | 21           |
| Telnet       | `telnet`              | 23           |
| SNMP         | `snmp`                | 161          |
| RDP          | `rdp`                 | 3389         |
| VNC          | `vnc`                 | 5900         |
| NetBIOS      | `netbios`             | 139          |
| SMB          | `smb`                 | 445          |
| PostgreSQL   | `postgresql`          | 5432         |
| MySQL        | `mysql`               | 3306         |
| Redis        | `redis`               | 6379         |
| Elasticsearch| `elasticsearch`       | 9200         |
| RabbitMQ     | `rabbitmq`            | 5672         |
| Kibana       | `kibana`              | 5601         |
| Node.js app  | `nodejs`              | 3000         |

---

## Minimal Working Example

```json
{
  "scenario_name": "minimal_example",
  "description": "One host running HTTP and SSH. HTTP must be closed.",
  "hosts": [
    {
      "id": "webserver",
      "features": [
        {
          "service": "http",
          "port": 80
        },
        {
          "service": "ssh",
          "port": 22
        }
      ]
    }
  ],
  "policy": {
    "forbidden_ports": [80],
    "forbidden_services": []
  }
}
```

---

## Realistic Example with Dependencies

```json
{
  "scenario_name": "two_tier_app",
  "description": "A web frontend that depends on a backend API.",
  "hosts": [
    {
      "id": "frontend",
      "features": [
        {
          "service": "http",
          "port": 80,
          "depends_on_service": [
            { "host": "backend", "service": "nodejs" }
          ]
        },
        {
          "service": "ssh",
          "port": 22
        }
      ]
    },
    {
      "id": "backend",
      "features": [
        {
          "service": "nodejs",
          "port": 3000,
          "critical": true,
          "vulnerable": true
        },
        {
          "service": "ftp",
          "port": 21
        },
        {
          "service": "ssh",
          "port": 22
        }
      ]
    }
  ],
  "policy": {
    "forbidden_ports": [80, 21],
    "forbidden_services": ["ftp"]
  }
}
```

In this example:
- `frontend`'s `http` service depends on `backend`'s `nodejs` — the planner will not block `nodejs` until it handles `frontend` first.
- `nodejs` is `critical` and `vulnerable` — the planner will patch it (not disable it).
- `ftp` is both forbidden as a service and running on a forbidden port — the planner will disable it.

---

## See Also

- Full reference scenarios: `input/scenarios/`
- Full use-case scenarios: `input/use_cases/`
- Planner configuration (action costs, alternative ports): `planner/conf.py`
- Main README: `README.md`
