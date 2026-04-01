from unified_planning.shortcuts import Not, MinimizeActionCosts, Object, Compiler, OneshotPlanner
from unified_planning.engines import CompilationKind
from .domain import NetworkHardeningDomain
from .conf import SERVICE_PORT_MAPPING, ALTERNATIVE_PORTS, ACTION_COSTS


class NetworkHardeningProblem:
    """
    Problem class for the network hardening problem. 
    It takes a scenario as input, which describes the initial state of the network (hosts, services, ports, etc.) 
    and the security policy (e.g., forbidden ports). The class then sets up the planning problem 
    by defining the objects, initial state, goals, and action costs based on the provided scenario. 
    Finally, it provides a method to solve the problem using a planner (e.g., Fast-Downward) and returns the result.

    The main components of the class include:
    - __init__(scenario): Initializes the problem with the given scenario, sets up the domain and problem, and preprocesses the host data.
    - setup_problem(scenario): Sets up the planning problem by defining objects, initial state, goals, and action costs based on the scenario.
    - solve(): Solves the planning problem using a planner and returns the result and the number of grounded actions.
    """
    def __init__(self, scenario):
        self.domain = NetworkHardeningDomain()
        self.problem = self.domain.get_problem()
        self.objects = {}
        self.scenario = scenario

        self.mapping = get_port_mapping(scenario)
        self.forbidden = scenario['policy'].get('forbidden_ports', [])

        self.host_service_ports = {}
        self.host_open_ports = {}
        for h in scenario['hosts']:
            service_to_port, open_ports = get_port_host_mapping(h, self.mapping)
            self.host_service_ports[h['id']] = service_to_port
            self.host_open_ports[h['id']] = open_ports

        self.setup_problem()

        
    def setup_problem(self):
        self.setup_objects()
        self.setup_initial_state()
        self.setup_goal()


    def setup_objects(self):
        """
        Set up the objects in the planning problem based on the scenario.
        This includes creating Object instances for hosts, ports, and services, and adding them to the problem.
        """

        # HOSTS
        for host in self.scenario['hosts']:
            key = host['id']
            Htype = self.domain.get_types()['Host']
            obj = Object(key, Htype)
            self.objects[key] = obj
            self.problem.add_object(obj)

        # PORTS
        all_ports = set()
        for port in self.host_open_ports.values():
            all_ports.update(port)
        for port in self.forbidden:
            all_ports.add(port)
            if port in ALTERNATIVE_PORTS:
                all_ports.add(ALTERNATIVE_PORTS[port])

        for port in sorted(all_ports):
            key = f'port_{port}'
            Ptype = self.domain.get_types()['Port']
            obj = Object(key, Ptype)
            self.objects[key] = obj
            self.problem.add_object(obj)

        # SERVICES
        all_services = set()
        for host in self.scenario['hosts']:
            for srv in host.get('features', []):
                all_services.add(srv['service'])

        for service in sorted(all_services):
            key = f'srv_{service}'
            Stype = self.domain.get_types()['Service']
            obj = Object(key, Stype)
            self.objects[key] = obj
            self.problem.add_object(obj)


    def setup_initial_state(self):
        """ 
        Set up the initial state of the planning problem based on the scenario.
        This involves setting the initial values of the fluents (e.g., which ports are open
        on which hosts, which services are active, etc.) according to the data provided in the scenario.
        """

        for host in self.scenario['hosts']:
            host_id = host['id']
            host_obj = self.objects[host_id]
            service_to_port = self.host_service_ports[host_id]
            open_ports = self.host_open_ports[host_id]

            # OPEN_PORT
            for port in open_ports:
                open_port_fluent = self.domain.get_fluents()['open_port']
                open_port_obj = self.objects[f'port_{port}']
                self.problem.set_initial_value(
                    open_port_fluent(host_obj, open_port_obj),
                    True
                )

            # SERVICE_ACTIVE and SERVICE_USES_PORT
            for service, port in service_to_port.items():
                active_service_fluent = self.domain.get_fluents()['service_active']
                active_service_obj = self.objects[f'srv_{service}']
                service_uses_port_fluent = self.domain.get_fluents()['service_uses_port']
                open_port_obj = self.objects[f'port_{port}']

                self.problem.set_initial_value(
                    active_service_fluent(host_obj, active_service_obj),
                    True
                )
                self.problem.set_initial_value(
                    service_uses_port_fluent(host_obj, active_service_obj, open_port_obj),
                    True
                )

            # SERVICE_CRITICAL and DEPENDS_ON
            for service in host.get('features', []):
                service_name = service['service']
                service_obj = self.objects.get(f'srv_{service_name}')

                if service_obj is None:
                    continue

                # SERVICE_CRITICAL
                if service.get("critical", False):
                    service_critical_fluent = self.domain.get_fluents()['service_critical']
                    self.problem.set_initial_value(
                        service_critical_fluent(host_obj, service_obj),
                        True
                    )

                # DEPENDS_ON
                for base in service.get("depends_on", []):
                    base_service_obj = self.objects.get(f"srv_{base}")
                    if base_service_obj is None:
                        continue
                    depends_on_fluent = self.domain.get_fluents()['depends_on']
                    self.problem.set_initial_value(
                        depends_on_fluent(host_obj, service_obj, base_service_obj),
                        True
                    )


    def setup_goal(self):
        """
        Set up the goals of the planning problem based on the scenario and the security policy.
        This involves defining the desired conditions that must be satisfied in the final state of the plan 
        (e.g., certain ports must be closed, certain services must be deactivated, etc.) according to the security 
        policy specified in the scenario.
        """

        # GOAL
        for host_id, open_ports in self.host_open_ports.items():
            host_obj = self.objects[host_id]
            for p in self.forbidden:
                if p in open_ports:
                    port_obj = self.objects.get(f'port_{p}')
                    if port_obj is None:
                        continue
                    open_port_fluent = self.domain.get_fluents()['open_port']
                    self.problem.add_goal(
                        Not(open_port_fluent(host_obj, port_obj))
                    )

        # ACTION COSTS
        cost_map = {}
        for action in self.problem.actions:
            name = action.name.lower()
            if 'close_port' in name:
                cost_map[action] = ACTION_COSTS['close_port']
            elif 'disable_service' in name:
                cost_map[action] = ACTION_COSTS['disable_service']
            elif 'migrate_service' in name:
                cost_map[action] = ACTION_COSTS['migrate_service']

        if cost_map:
            self.problem.add_quality_metric(MinimizeActionCosts(cost_map))


    def solve(self):
        """
        Solve the planning problem using Fast-Downward. 
        The method first compiles the problem using the specified compilation kind (grounding), 
        then uses the OneshotPlanner with Fast-Downward to find a solution. 
        It is a forward search planner that finds a plan that achieves the goals from the initial state.

        If a plan is found, it maps the grounded actions back to their original representations. 
        Finally, it returns the planner result and the number of grounded actions in the compiled problem.

        Returns:
            result: planner result (contains plan if found)
            ground_actions: number of grounded actions
        """
        try:
            with Compiler(
                problem_kind=self.problem.kind,
                compilation_kind=CompilationKind.GROUNDING
            ) as compiler:

                compiled = compiler.compile(self.problem)

                with OneshotPlanner(name='fast-downward') as planner:
                    result = planner.solve(compiled.problem)

                    # FIX: guard su result.plan None prima di accedervi
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

def get_port_mapping(scenario):
    """
    Build the port mapping from the scenario, starting with the default SERVICE_PORT_MAPPING
    and then overriding with any explicit port definitions in the scenario features.
    Return: {service_name: port, ...}
    """
    port_mapping = SERVICE_PORT_MAPPING.copy()

    for host in scenario['hosts']:
        for feature in host['features']:
            service = feature['service']
            if "port" in feature:
                # FIX: assegna scalare intero, non lista
                port_mapping[service] = feature["port"]

    return port_mapping


def get_port_host_mapping(host, port_mapping, default_port=10000):
    """
    For a given host, build a mapping of services to ports and a set of open ports.
    Return: ({service_name: port, ...}, {open_port1, open_port2, ...})
    """
    service_to_port = {}
    open_ports = set()

    for feature in host['features']:
        if "service" not in feature:
            continue

        service = feature['service']

        if "port" in feature:
            port = feature["port"]
        elif service in port_mapping:
            port = port_mapping[service]
        else:
            port = default_port

        open_ports.add(port)
        service_to_port[service] = port

    return service_to_port, open_ports


def get_dependent_services(host_id, service, scenario):
    """
    For a given host and service, find all services that depend on it.
    Return: [dependent_service1, dependent_service2, ...]
    """
    for host in scenario.get("hosts", []):
        if host["id"] == host_id:
            result = []
            for feature in host['features']:
                if service in feature.get("depends_on", []):
                    result.append(feature['service'])
            return result

    return []