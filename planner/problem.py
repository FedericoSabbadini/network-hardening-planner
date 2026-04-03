from unified_planning.shortcuts import (
    Not, MinimizeActionCosts, Object, Compiler, OneshotPlanner,
    Int, Exists, And, Variable
)
from unified_planning.engines import CompilationKind, OptimalityGuarantee
from .domain import NetworkHardeningDomain
from .conf import ALTERNATIVE_PORTS, ACTION_COSTS, SERVICE_PORTS


class NetworkHardeningProblem:

    def __init__(self, scenario):
        self.domain = NetworkHardeningDomain()
        self.problem = self.domain.get_problem()
        self.objects = {}
        self.scenario = scenario

        self.forbiddenP = scenario['policy'].get('forbidden_ports', [])
        self.forbiddenS = scenario['policy'].get('forbidden_services', [])
        self.serv_ports = SERVICE_PORTS.copy()

        self.host_service_ports = {}
        self.host_open_ports = {}
        for h in scenario['hosts']:
            service_to_port, open_ports = get_port_host_mapping(h)
            self.host_service_ports[h['id']] = service_to_port
            self.host_open_ports[h['id']] = open_ports

        self.setup_problem()

    def setup_problem(self):
        self.setup_objects()
        self.setup_initial_state()
        self.setup_goal()

    def setup_objects(self):
        # HOSTS
        for host in self.scenario['hosts']:
            key = host['id']
            obj = Object(key, self.domain.get_types()['Host'])
            self.objects[key] = obj
            self.problem.add_object(obj)

        # PORTS
        all_ports = set()
        for port in self.host_open_ports.values():
            all_ports.update(port)
        for port in self.forbiddenP:
            if port in ALTERNATIVE_PORTS:
                all_ports.add(ALTERNATIVE_PORTS[port])
        for port in SERVICE_PORTS:
            all_ports.add(port)

        for port in sorted(all_ports):
            key = f'port_{port}'
            obj = Object(key, self.domain.get_types()['Port'])
            self.objects[key] = obj
            self.problem.add_object(obj)

        # SERVICES
        all_services = set()
        for host in self.scenario['hosts']:
            for srv in host.get('features', []):
                all_services.add(srv['service'])

        for service in sorted(all_services):
            key = f'srv_{service}'
            obj = Object(key, self.domain.get_types()['Service'])
            self.objects[key] = obj
            self.problem.add_object(obj)

    def setup_initial_state(self):
        fluents = self.domain.get_fluents()


        for port in self.forbiddenP:
            port_obj = self.objects.get(f'port_{port}')
            if port_obj:
                self.problem.set_initial_value(fluents['port_forbidden'](port_obj), True)
        
        for service in self.forbiddenS:
            service_obj = self.objects.get(f'srv_{service}')
            if service_obj:
                self.problem.set_initial_value(fluents['service_forbidden'](service_obj), True)

        hosts_needing_open_possibility = {
            h['id']
            for h in self.scenario['hosts']
            for feat in h.get('features', [])
            if (feat.get('port') in self.forbiddenP
                and feat['service'] not in self.forbiddenS
                and (ALTERNATIVE_PORTS.get(feat.get('port')) is None
                    or ALTERNATIVE_PORTS.get(feat.get('port')) in self.forbiddenP))
        }

        for host in self.scenario['hosts']:
            host_id = host['id']
            host_obj = self.objects[host_id]

            # OPEN_PORT
            for port in self.host_open_ports[host_id]:
                self.problem.set_initial_value(
                    fluents['open_port'](host_obj, self.objects[f'port_{port}']), True
                )

            # Singolo pass sulle features
            for feature in host.get('features', []):
                service_name = feature['service']
                port = feature.get('port')
                service_obj = self.objects.get(f'srv_{service_name}')
                if service_obj is None:
                    continue

                # SERVICE_ACTIVE + SERVICE_USES_PORT + MIGRATE_POSSIBILITY
                self.problem.set_initial_value(fluents['service_active'](host_obj, service_obj), True)
                if port is not None:
                    port_obj = self.objects[f'port_{port}']
                    self.problem.set_initial_value(
                        fluents['service_uses_port'](host_obj, service_obj, port_obj), True
                    )
                    self.problem.set_initial_value(
                        fluents['service_reachable'](host_obj, service_obj), True
                    )
                    alt_port = ALTERNATIVE_PORTS.get(port)
                    if alt_port is not None:
                        alt_port_obj = self.objects.get(f'port_{alt_port}')
                        if alt_port_obj:
                            self.problem.set_initial_value(
                                fluents['migrate_possibility'](host_obj, service_obj, port_obj, alt_port_obj), True
                            )

                # CRITICAL + VULNERABLE
                if feature.get('critical'):
                    self.problem.set_initial_value(fluents['service_critical'](host_obj, service_obj), True)
                if feature.get('vulnerable'):
                    self.problem.set_initial_value(fluents['service_vulnerable'](host_obj, service_obj), True)

                # DEPENDS_ON
                for dep in feature.get('depends_on_service', []):
                    base_host_obj = self.objects.get(dep['host'])
                    base_service_obj = self.objects.get(f'srv_{dep["service"]}')
                    if base_host_obj and base_service_obj:
                        self.problem.set_initial_value(
                            fluents['depends_on'](host_obj, service_obj, base_host_obj, base_service_obj), True
                        )


            # OPEN_POSSIBILITY: solo per host che ne hanno bisogno
            if host_id in hosts_needing_open_possibility:
                for srv_port in SERVICE_PORTS:
                    if srv_port in self.forbiddenP:
                        continue
                    port_obj = self.objects.get(f'port_{srv_port}')
                    if port_obj:
                        self.problem.set_initial_value(
                            fluents['open_possibility'](host_obj, port_obj), True
                        )

    def setup_goal(self):
        fluents = self.domain.get_fluents()

        for host in self.scenario['hosts']:
            host_id = host['id']
            host_obj = self.objects[host_id]

            for feature in host.get('features', []):
                service_name = feature['service']
                port = feature.get('port')
                service_obj = self.objects.get(f'srv_{service_name}')

                # GOAL 1: Fix vulnerable services (only if service is not forbidden — patch is applicable)
                if feature.get('vulnerable', False) and service_obj is not None and service_name not in self.forbiddenS:
                    self.problem.add_goal(Not(fluents['service_vulnerable'](host_obj, service_obj)))

                # GOAL 2: Close forbidden ports
                if port in self.forbiddenP:
                    port_obj = self.objects.get(f'port_{port}')
                    if port_obj is not None:
                        self.problem.add_goal(Not(fluents['open_port'](host_obj, port_obj)))

                # GOAL 3: Disable forbidden services
                if service_name in self.forbiddenS and service_obj is not None:
                    self.problem.add_goal(Not(fluents['service_active'](host_obj, service_obj)))

                # GOAL 4: Services on a forbidden port but NOT forbidden must remain
                # reachable on some non-forbidden open port.
                if port in self.forbiddenP and service_name not in self.forbiddenS:
                    self.problem.add_goal(
                        fluents['service_reachable'](host_obj, service_obj)
                    )

        # ACTION COSTS
        cost_map = {}
        for action in self.problem.actions:
            name = action.name.lower()
            if 'block_port_firewall' in name:
                cost_map[action] = Int(ACTION_COSTS['block_port_firewall'])
            elif 'disable_service' in name:
                cost_map[action] = Int(ACTION_COSTS['disable_service'])
            elif 'migrate_service' in name:
                cost_map[action] = Int(ACTION_COSTS['migrate_service'])
            elif 'patch_service' in name:
                cost_map[action] = Int(ACTION_COSTS['patch_service'])
            elif 'reuse_service' in name:
                cost_map[action] = Int(ACTION_COSTS['reuse_service'])
            elif 'reuse_vulnerable_service' in name:
                cost_map[action] = Int(ACTION_COSTS['reuse_vulnerable_service'])
            elif 'disable_vulnerable_service' in name:
                cost_map[action] = Int(ACTION_COSTS['disable_vulnerable_service'])
            elif 'patch_critical_service' in name:
                cost_map[action] = Int(ACTION_COSTS['patch_critical_service'])

        if cost_map:
            self.problem.add_quality_metric(MinimizeActionCosts(cost_map, default=Int(1)))

    # ------------------------------------------------------------------
    # SOLVE  — three-stage compilation + optimal Fast Downward
    # ------------------------------------------------------------------
    def solve(self):
        try:
            with Compiler(
                problem_kind=self.problem.kind,
                compilation_kind=CompilationKind.GROUNDING
            ) as compiler:
                compiled = compiler.compile(self.problem)

                with OneshotPlanner(name='fast-downward', optimality_guarantee=OptimalityGuarantee.SOLVED_OPTIMALLY
                ) as planner:
                    result = planner.solve(compiled.problem)

                    if result.plan:
                        result.plan = result.plan.replace_action_instances(
                            compiled.map_back_action_instance
                        )

                    return result, len(list(compiled.problem.actions))

        except Exception as e:
            print(f"Error during planning: {str(e)[:100]}")
            return None, 0


# =========================
# UTILITIES
# =========================

def get_port_host_mapping(host, default_port=9999):
    service_to_port = {}
    open_ports = set()
    for feature in host['features']:
        service = feature['service']
        port = feature['port']
        if port is None:
            port = default_port
        open_ports.add(port)
        service_to_port[service] = port
    return service_to_port, open_ports


def get_dependent_services(host_id, service, scenario):
    """
    Restituisce lista di (host_id, service) che dipendono da (host_id, service).
    Aggiornato per il nuovo formato depends_on_service.
    """
    result = []
    for host in scenario.get('hosts', []):
        for feature in host['features']:
            for dep in feature.get('depends_on_service', []):
                if dep['host'] == host_id and dep['service'] == service:
                    result.append((host['id'], feature['service']))
    return result