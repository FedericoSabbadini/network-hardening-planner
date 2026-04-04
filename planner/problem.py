from unified_planning.shortcuts import (
    Not, MinimizeActionCosts, Object, Compiler, OneshotPlanner, Int
)
from unified_planning.engines import CompilationKind, OptimalityGuarantee
from .domain import NetworkHardeningDomain
from .conf import ALTERNATIVE_PORTS, ACTION_COSTS, SERVICE_PORTS


class NetworkHardeningProblem:
    """
    Problem class for the network hardening problem.
    Initializes objects, initial state, and goals based on the scenario.
    """

    def __init__(self, scenario):
        self.domain = NetworkHardeningDomain()
        self.problem = self.domain.get_problem()
        self.fluents = self.domain.get_fluents()      
        self.objects = {}
        self.scenario = scenario

        self.forbiddenP = scenario['policy'].get('forbidden_ports', [])
        self.forbiddenS = scenario['policy'].get('forbidden_services', [])
        self.serv_ports = SERVICE_PORTS.copy()

        self.host_service_ports = {}
        self.host_open_ports = {}
        for h in scenario['hosts']:
            service_to_port, open_ports = self._get_port_host_mapping(h)
            self.host_service_ports[h['id']] = service_to_port
            self.host_open_ports[h['id']] = open_ports

        self.setup_problem()

    # ------------------------------------------------------------------
    # PRIVATE HELPERS
    # ------------------------------------------------------------------

    def _get_port_host_mapping(self, host, default_port=9999):
        service_to_port = {}
        open_ports = set()
        for feature in host['features']:
            service = feature['service']
            port = feature['port'] if feature['port'] is not None else default_port
            open_ports.add(port)
            service_to_port[service] = port
        return service_to_port, open_ports


    def _get_dependent_services(self, host_id, service, scenario):
        """Returns list of (host_id, service) that depend on (host_id, service)."""
        return [
            (host['id'], feature['service'])
            for host in scenario.get('hosts', [])
            for feature in host['features']
            for dep in feature.get('depends_on_service', [])
            if dep['host'] == host_id and dep['service'] == service
        ]

    def _add_object(self, key, type_name):
        """Create, register, and return a typed UP Object."""
        obj = Object(key, self.domain.get_types()[type_name])
        self.objects[key] = obj
        self.problem.add_object(obj)
        return obj

    def _port_obj(self, port):
        return self.objects.get(f'port_{port}')

    def _srv_obj(self, service):
        return self.objects.get(f'srv_{service}')

    def _set_init(self, fluent_expr, value=True):
        self.problem.set_initial_value(fluent_expr, value)

    def _build_cost_map(self):
        """Map each action to its cost based on ACTION_COSTS key matching."""
        cost_map = {}
        for action in self.problem.actions:
            name = action.name.lower()
            for key, cost in ACTION_COSTS.items():
                if key in name:
                    cost_map[action] = Int(cost)
                    break
        return cost_map

    # ------------------------------------------------------------------
    # SETUP
    # ------------------------------------------------------------------

    def setup_problem(self):
        self.setup_objects()
        self.setup_initial_state()
        self.setup_goal()


    def setup_objects(self):
        """
         Create UP objects for hosts, ports, and services based on the scenario, forall the types defined in the domain.
         - Hosts: one object per host ID
         - Ports: one object per unique port across all hosts, forbidden ports, and service ports
         - Services: one object per unique service across all hosts
         """
        # ------------------- HOSTS -------------------
        for host in self.scenario['hosts']:
            key = host['id']
            obj = Object(key, self.domain.get_types()['Host'])
            self.objects[key] = obj
            self.problem.add_object(obj)

        # ------------------- PORTS -------------------
        all_ports = set()
        for port in self.host_open_ports.values():
            all_ports.update(port)
        for port in self.forbiddenP: 
            if port in ALTERNATIVE_PORTS:
                all_ports.add(ALTERNATIVE_PORTS[port])
                # I add the alternative port to the objects even if it's not currently used by any service, 
                # because it may be used in the future if a service is migrated to it.
        for port in SERVICE_PORTS:
            all_ports.add(port)
            # I add all service ports to the objects even if they are not currently used by any service,
            # because they may be used in the future if a service is migrated to them.

        for port in sorted(all_ports):
            key = f'port_{port}'
            obj = Object(key, self.domain.get_types()['Port'])
            self.objects[key] = obj
            self.problem.add_object(obj)

        # ------------------- SERVICES -------------------
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
        """
         Setup initial state based on the scenario, forall the fluents defined in the domain:
         - Open ports
         - Active services
         - Service-port associations
         - Forbidden ports and services
         - Open possibility for hosts that have services on forbidden ports without usable alternatives
         - Service dependencies
         """
        f = self.fluents

        # Global forbidden ports (not per-host)
        for port in self.forbiddenP:
            port_obj = self._port_obj(port)
            if port_obj:
                self._set_init(f['port_forbidden'](port_obj))

        # Global forbidden services (not per-host)
        for service in self.forbiddenS:
            srv_obj = self._srv_obj(service)
            if srv_obj:
                self._set_init(f['service_forbidden'](srv_obj))

        # Hosts that need open_possibility: those that have at least one service on a forbidden 
        # port without a usable alternative port
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

            # Open ports, based on the host_open_ports mapping
            for port in self.host_open_ports[host_id]:
                self._set_init(f['open_port'](host_obj, self._port_obj(port)))


            for feature in host.get('features', []):
                service_name = feature['service']
                port = feature.get('port')
                srv_obj = self._srv_obj(service_name)
                if srv_obj is None:
                    continue
                # service active on the host
                self._set_init(f['service_active'](host_obj, srv_obj))

                if port is not None:
                    port_obj = self._port_obj(port)
                    # service uses the port
                    self._set_init(f['service_uses_port'](host_obj, srv_obj, port_obj))
                    # service reachable if it's not forbidden
                    self._set_init(f['service_reachable'](host_obj, srv_obj))

                    alt_port = ALTERNATIVE_PORTS.get(port)
                    if alt_port:
                        alt_port_obj = self._port_obj(alt_port)
                        if alt_port_obj:
                            # migrate possibility if the current port is forbidden and the alternative port is not forbidden
                            self._set_init(f['migrate_possibility'](host_obj, srv_obj, port_obj, alt_port_obj))

                if feature.get('critical'):
                    # critical service on the host
                    self._set_init(f['service_critical'](host_obj, srv_obj))
                if feature.get('vulnerable'):
                    # vulnerable service on the host
                    self._set_init(f['service_vulnerable'](host_obj, srv_obj))

                for dep in feature.get('depends_on_service', []):
                    dep_host_obj = self.objects.get(dep['host'])
                    dep_srv_obj = self._srv_obj(dep['service'])
                    if dep_host_obj and dep_srv_obj:
                        # service dependency on the host
                        self._set_init(f['depends_on'](host_obj, srv_obj, dep_host_obj, dep_srv_obj))

            # Open possibility (only for hosts that need it)
            if host_id in hosts_needing_open_possibility:
                for srv_port in SERVICE_PORTS:
                    if srv_port not in self.forbiddenP:
                        port_obj = self._port_obj(srv_port)
                        if port_obj:
                            # I set open_possibility for all non-forbidden service ports, because the vulnerable service may need to migrate to any of them if its current port is forbidden and has no usable alternative.
                            self._set_init(f['open_possibility'](host_obj, port_obj))

    
    def setup_goal(self):
        """
        Setup goals based on the scenario and policy:
        G1: fix vulnerable non-forbidden services
        G2: close forbidden ports
        G3: disable forbidden services
        G4: non-forbidden services must stay reachable
        G5: if the vulnerable service is using a port not forbidden, it should keep using it (i.e., it should not be migrated to another port, because migrating may cause unexpected service issues, and if the service is not forbidden and its port is not forbidden, then there is no reason to migrate it to another port)"""
        f = self.fluents

        for host in self.scenario['hosts']:
            host_obj = self.objects[host['id']]

            for feature in host.get('features', []):
                service_name = feature['service']
                port = feature.get('port')
                srv_obj = self._srv_obj(service_name)

                # G1: fix vulnerable non-forbidden services
                if feature.get('vulnerable') and srv_obj and service_name not in self.forbiddenS:
                    self.problem.add_goal(Not(f['service_vulnerable'](host_obj, srv_obj)))
                    # G5: if the vulnerable service is using a port not forbidden, it should keep using it (i.e., it should not be migrated to another port, because migrating may cause unexpected service issues, and if the service is not forbidden and its port is not forbidden, then there is no reason to migrate it to another port)
                    if port not in self.forbiddenP:
                        port_obj = self._port_obj(port)
                        if port_obj:
                            self.problem.add_goal(f['service_uses_port'](host_obj, srv_obj, port_obj))

                # G2: close forbidden ports
                if port in self.forbiddenP:
                    port_obj = self._port_obj(port)
                    if port_obj:
                        self.problem.add_goal(Not(f['open_port'](host_obj, port_obj)))

                # G3: disable forbidden services
                if service_name in self.forbiddenS and srv_obj:
                    self.problem.add_goal(Not(f['service_active'](host_obj, srv_obj)))

                # G4: non-forbidden services must stay reachable
                if service_name not in self.forbiddenS:
                    self.problem.add_goal(f['service_reachable'](host_obj, srv_obj))


        cost_map = self._build_cost_map()
        if cost_map:
            self.problem.add_quality_metric(MinimizeActionCosts(cost_map, default=Int(1)))
            # I add a default cost of 1 for any action not explicitly listed in ACTION_COSTS, to ensure that all actions have a cost and the planner can optimize properly.


    # ------------------------------------------------------------------
    # SOLVE — grounding + optimal Fast Downward
    # ------------------------------------------------------------------
    def solve(self):
        """
         Ground the problem and solve it using Fast Downward with optimality guarantee.
         Returns the plan and the number of grounded actions.
         If an error occurs during planning, returns None and 0.
         """
        try:
            with Compiler(
                problem_kind=self.problem.kind,
                compilation_kind=CompilationKind.GROUNDING
            ) as compiler:
                # Ground the problem and get the mapping back to original action instances
                # This is necessary because the planner will return plans with grounded action instances,
                # and we want to map them back to the original action instances for readability.
                compiled = compiler.compile(self.problem)

                with OneshotPlanner(
                    name='fast-downward',
                    optimality_guarantee=OptimalityGuarantee.SOLVED_OPTIMALLY
                ) as planner:
                    result = planner.solve(compiled.problem)
                    # Map the plan back to original action instances for readability
                    # Note: the plan may be None if the problem is unsolvable, so I check before mapping back.
                    if result.plan:
                        result.plan = result.plan.replace_action_instances(
                            compiled.map_back_action_instance
                        )

                    return result, len(list(compiled.problem.actions))

        except Exception as e:
            print(f"Error during planning: {str(e)[:100]}")
            return None, 0