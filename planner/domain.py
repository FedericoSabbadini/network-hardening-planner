from unified_planning.shortcuts import Problem, UserType, Fluent, BoolType, InstantaneousAction, Variable, Forall, Implies, Not


class NetworkHardeningDomain:
    """
    Domain class for the network hardening problem. It defines the types, fluents, and actions that can be used in the planning problem. 
    The domain is designed to model a network of hosts, services, and ports, and to allow for actions that can harden the network by closing ports, deactivating services, etc.
   
    The domain includes the following components:
    - Types: Host, Port, Service
    - Fluents: open_port(host, port), service_active(host, service), service_critical(host, service), service_uses_port(host, service, port), depends_on(host, dependent_service, base_service)
    - Actions: close_port(host, port), deactivate_service(host, service), patch_service(host, service), add_firewall_rule(host, port)
    """

    def __init__(self):

        # === PLANNING PROBLEM ===
        # Planning proble associated to this domain
        self.problem = Problem('network_hardening')


        # ========= TYPES DEFINITION =========
        Host = UserType('Host') # Host = computer, server, device
        Port = UserType('Port')  # Port = network port (e.g., 80, 443)
        Service = UserType('Service') # Service = software service running on a host (e.g., web server, database)
        # Define object types used in the domain, to instantiate objects in the problem
        self.types = {
            'Host': Host, 
            'Port': Port, 
            'Service': Service
        }
        for type_name, type_obj in self.types.items():
            self.problem.add_type(type_obj)


        # ========= FLUENTS DEFINITION =========
        open_port = Fluent('open_port', BoolType(), host=Host, port=Port)  # open_port(host, port) = True if the specified port is open on the specified host
        service_active = Fluent('service_active', BoolType(), host=Host, service=Service)  # service_active(host, service) = True if the specified service is active on the specified host
        service_critical = Fluent('service_critical', BoolType(), host=Host, service=Service) # service_critical(host, service) = True if the specified service is critical for the specified host (i.e., it is essential for the host's operation or security)
        service_uses_port = Fluent('service_uses_port', BoolType(), host=Host, service=Service, port=Port) # service_uses_port(host, service, port) = True if the specified service on the specified host uses the specified port (i.e., it listens on that port for incoming connections)
        depends_on = Fluent('depends_on', BoolType(), host=Host, dependent_service=Service, base_service=Service) # depends_on(host, dependent_service, base_service) = True if the specified dependent service on the specified host depends on the specified service active on some other host (i.e., it requires the base service to be active in order to function properly)
        # Define fluents (facts/predicates) used in the domain, to describe the state of the world
        # They are boolean predicates that can be true or false, and have parameters (e.g., host, port, service)
        self.fluents = {
            'open_port': open_port,
            'service_active': service_active,
            'service_critical': service_critical,
            'service_uses_port': service_uses_port,
            'depends_on': depends_on
        }
        for fluent in self.fluents.values():
            self.problem.add_fluent(fluent, default_initial_value=False)


        # ========= ACTIONS =========
        # 3 actions are defined in the domain, to allow for changes in the state of the world. 
        # Each action has parameters, preconditions that must be satisfied for the action to be applicable, and effects that describe how the action changes the state of the world.

        # ------ 1. disable_service(host, service) ------
        # Action interface
        disable_service_action = InstantaneousAction('disable_service', host=Host, service=Service)
        # Action parameters
        h = disable_service_action.parameter('host')
        s = disable_service_action.parameter('service')
        # Action preconditions
        disable_service_action.add_precondition(service_active(h, s)) # the service must be active to be disabled
        disable_service_action.add_precondition(Not(service_critical(h, s))) # the service must not be critical to be disabled (i.e., it can be safely disabled without causing major issues to the host)

        s2 = Variable('s2', Service)
        h2 = Variable('h2', Host)
        disable_service_action.add_precondition( # if there is a service s2 on host h2 so that service s on host h depends to it, s2 must not be active in order to disable s
            Forall(
                s2, h2,
                Implies(
                    depends_on(h2, s2, s), # if there is a service s2 on host h2 so that service s on host h depends to it, s2 must not be active in order to disable s
                    Not(service_active(h2, s2)) # s2 must not be active
                )
            )
        )
        # Action effects
        disable_service_action.add_effect(service_active(h, s), False)

        self.problem.add_action(disable_service_action)


        # ------ 2. close_port(host, port) ------
        # Action interface
        close_port_action = InstantaneousAction('close_port', host=Host, port=Port)
        # Action parameters
        h = close_port_action.parameter('host')
        p = close_port_action.parameter('port')
        # Action preconditions
        close_port_action.add_precondition(open_port(h, p)) # the port must be open to be closed

        s = Variable('s', Service)
        close_port_action.add_precondition( # if there is a service s on host h that uses port p, s must not be active in order to close p
            Forall(
                s,
                Implies(
                    service_uses_port(h, s, p),
                    Not(service_active(h, s))
                )
            )
        )
        # Action effects
        close_port_action.add_effect(open_port(h, p), False)

        self.problem.add_action(close_port_action)


        # ------ 3. migrate_service(h, s, p_old, p_new) ------
        # Action interface
        migrate_service_action = InstantaneousAction('migrate_service', h=Host, s=Service, p_old=Port, p_new=Port)
        # Action parameters
        h = migrate_service_action.parameter('h')
        s = migrate_service_action.parameter('s')
        p_old = migrate_service_action.parameter('p_old')
        p_new = migrate_service_action.parameter('p_new')
        # Action preconditions
        migrate_service_action.add_precondition(service_active(h, s)) # the service must be active to be migrated
        migrate_service_action.add_precondition(open_port(h, p_old)) # the old port must be open to be migrated
        migrate_service_action.add_precondition(Not(open_port(h, p_new))) # the new port must be closed to be migrated
        migrate_service_action.add_precondition(service_uses_port(h, s, p_old)) # the service must use the old port to be migrated
        # Action effects
        migrate_service_action.add_effect(open_port(h, p_old), False)
        migrate_service_action.add_effect(open_port(h, p_new), True)
        migrate_service_action.add_effect(service_uses_port(h, s, p_old), False)
        migrate_service_action.add_effect(service_uses_port(h, s, p_new), True)

        self.problem.add_action(migrate_service_action)
        self.actions = {
            'disable_service': disable_service_action,
            'close_port': close_port_action,
            'migrate_service': migrate_service_action
        }

    def get_problem(self):
        return self.problem
    
    def get_types(self):
        return self.types
    
    def get_fluents(self):
        return self.fluents
    
    def get_actions(self):
        return self.actions