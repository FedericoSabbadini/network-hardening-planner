from unified_planning.shortcuts import Problem, UserType, Fluent, BoolType, InstantaneousAction, Variable, Forall, Implies, Not, And


class NetworkHardeningDomain:
    """
    Domain class for the network hardening problem.

    Types: Host, Port, Service
    Fluents: open_port, service_active, service_critical, service_uses_port,
             depends_on(host, dependent_service, base_host, base_service),  ← cross-host
             migrate_possibility, service_vulnerable, port_forbidden, service_forbidden, open_possibility
    Actions: disable_service, block_port_firewall, migrate_service, patch_service, reuse_service
    """

    def __init__(self):

        self.problem = Problem('network_hardening')
        self.set_types()
        self.set_fluents()
        self.set_actions()

    def set_types(self):
        # ======== TYPES =========
        Host = UserType('Host')
        Port = UserType('Port')
        Service = UserType('Service')

        self.types = {'Host': Host, 'Port': Port, 'Service': Service}

    def set_fluents(self):
        # ========= FLUENTS =========
        open_port = Fluent('open_port', BoolType(), host=self.types['Host'], port=self.types['Port']) # open_port(host, port) = True if port is open on host (i.e., if it is possible for a service to use it), False if the port is closed on host (i.e., if it is not possible for a service to use it, for example because it is blocked by a firewall or because it is already used by another service)
        service_active = Fluent('service_active', BoolType(), host=self.types['Host'], service=self.types['Service']) # service_active(host, service) = True if service is active on host, False if it is disabled (in this case it is not active and not vulnerable)
        service_critical = Fluent('service_critical', BoolType(), host=self.types['Host'], service=self.types['Service']) # service_critical(host, service) = True if service is critical on host (i.e., if its downtime would cause unacceptable operational impact), False otherwise
        service_uses_port = Fluent('service_uses_port', BoolType(), host=self.types['Host'], service=self.types['Service'], port=self.types['Port']) # service_uses_port(host, service, port) = True if service on host uses port, False otherwise (in this case the service does not use the port, so it is not possible to block the port or migrate the service to another port without disabling the service)
        depends_on = Fluent('depends_on', BoolType(), host=self.types['Host'], dependent_service=self.types['Service'], base_host=self.types['Host'], base_service=self.types['Service']) # depends_on(host, dependent_service, base_host, base_service) = True if dependent_service on host depends on base_service on base_host (i.e., if downtime of base_service on base_host would cause downtime of dependent_service on host), False otherwise (in this case there is no dependency between the two services, so it is possible to block the port used by base_service or migrate base_service to another port without causing downtime on dependent_service)
        migrate_possibility = Fluent('migrate_possibility', BoolType(), host=self.types['Host'], service=self.types['Service'], port_old=self.types['Port'], port_new=self.types['Port']) # migrate_possibility(host, service, port_old, port_new) = True if it is possible to migrate service on host from port_old to port_new (i.e., if port_old is a port used by service on host, port_new is an alternative to port_old or a free port, and migrating service from port_old to port_new would not cause unacceptable downtime), False otherwise (in this case it is not possible to migrate the service from port_old to port_new, so the only options to mitigate service vulnerabilities would be disabling or patching it)
        open_possibility = Fluent('open_possibility', BoolType(), port=self.types['Port']) # open_possibility(host, service, port) = True if it is possible to open port on host and let service use it (i.e., if port is an alternative to a forbidden port used by service, or if port is a free port that is not forbidden)
        service_vulnerable = Fluent('service_vulnerable', BoolType(), host=self.types['Host'], service=self.types['Service']) # service_vulnerable(host, service) = True if service on host is vulnerable (i.e., if it has one or more known vulnerabilities that have not been mitigated), False otherwise (in this case the service is not vulnerable, so it does not need mitigation)
        port_forbidden = Fluent('port_forbidden', BoolType(), port=self.types['Port']) # port_forbidden(port) = True if the port is forbidden by firewall or company policy (e.g., for security reasons), and therefore cannot be used by any service on that host
        service_forbidden = Fluent('service_forbidden', BoolType(), service=self.types['Service']) # service_forbidden(service) = True if the service is forbidden by company policy


        self.fluents = {
            'open_port': open_port,
            'service_active': service_active,
            'service_critical': service_critical,
            'service_uses_port': service_uses_port,
            'depends_on': depends_on,
            'migrate_possibility': migrate_possibility,
            'open_possibility': open_possibility,
            'service_vulnerable': service_vulnerable,
            'port_forbidden': port_forbidden,
            'service_forbidden': service_forbidden
        }
        for fluent in self.fluents.values():
            self.problem.add_fluent(fluent, default_initial_value=False)


    def set_actions(self):
        # ======== ACTIONS =========
        patch_service = self.set_patch_service()
        disable_service = self.set_disable_service()
        block_port_firewall = self.set_block_port_firewall()
        migrate_service = self.set_migrate_service()
        reuse_service = self.set_reuse_service()

        self.actions = {
            'patch_service': patch_service,
            'disable_service': disable_service,
            'block_port_firewall': block_port_firewall,
            'migrate_service': migrate_service,
            'reuse_service': reuse_service
        }
        for action in self.actions.values():
            self.problem.add_action(action)

    def set_disable_service(self): # this action is needed to disable a service that cannot be mitigated by blocking its ports or migrating it to other ports, for example because it is critical or because all its ports are forbidden. Disabling a service causes downtime on it, but it is the only option to mitigate its vulnerabilities in these cases.  
        # ========= INTERFACE =========
        disable_service_action = InstantaneousAction('disable_service', host=self.types['Host'], service=self.types['Service'])
        # ========= PARAMETERS =========
        h = disable_service_action.parameter('host')
        s = disable_service_action.parameter('service')
        # ========= PRECONDITIONS =========
        disable_service_action.add_precondition(self.fluents['service_active'](h, s))
        p = Variable('p', self.types['Port'])
        disable_service_action.add_precondition(
            Forall(
                Implies(self.fluents['service_uses_port'](h, s, p), 
                Not(self.fluents['open_port'](h, p))),
                p
            )
        )
        # ========= EFFECTS =========
        disable_service_action.add_effect(self.fluents['service_active'](h, s), False)
        disable_service_action.add_effect(self.fluents['service_vulnerable'](h, s), False)
        return disable_service_action

    def set_block_port_firewall(self): # this action is needed to block a port used by a non-critical service that cannot be migrated to another port, for example because all the alternative ports are forbidden or because there is no possibility to migrate it without causing unacceptable downtime. Blocking a port causes downtime on the service using it, but it allows to mitigate its vulnerabilities without disabling it.
        # ========= INTERFACE =========
        block_port_firewall_action = InstantaneousAction('block_port_firewall', host=self.types['Host'], port=self.types['Port'], service=self.types['Service'])
        # ========= PARAMETERS =========
        h = block_port_firewall_action.parameter('host')
        p = block_port_firewall_action.parameter('port')
        s = block_port_firewall_action.parameter('service')
        # ========= PRECONDITIONS =========
        block_port_firewall_action.add_precondition(self.fluents['open_port'](h, p))
        block_port_firewall_action.add_precondition(self.fluents['service_uses_port'](h, s, p)) 
        block_port_firewall_action.add_precondition(Not(self.fluents['service_critical'](h, s))) 
        h2 = Variable('h2', self.types['Host'])
        s2 = Variable('s2', self.types['Service'])
        block_port_firewall_action.add_precondition(
            Forall(
                Implies(self.fluents['depends_on'](h2, s2, h, s), 
                Not(self.fluents['service_active'](h2, s2))),
                h2, s2
            )
        )
        # ========= EFFECTS =========
        block_port_firewall_action.add_effect(self.fluents['open_port'](h, p), False)
        block_port_firewall_action.add_effect(self.fluents['service_uses_port'](h, s, p), False)
        return block_port_firewall_action
    
    def set_migrate_service(self): # this action is needed to migrate a service from a port to another port, for example to migrate it from a forbidden port to an allowed port, or to migrate it from a port that cannot be blocked (for example because it is used by other services that would be affected by blocking it) to a port that can be blocked. Migrating a service causes downtime on it, but it allows to mitigate its vulnerabilities without disabling it, and in some cases it is the only option to mitigate it without disabling it.
        # ========= INTERFACE =========
        migrate_service_action = InstantaneousAction('migrate_service', h=self.types['Host'], s=self.types['Service'], p_old=self.types['Port'], p_new=self.types['Port'])
        # ========= PARAMETERS =========
        h = migrate_service_action.parameter('h')
        s = migrate_service_action.parameter('s')
        p_old = migrate_service_action.parameter('p_old')
        p_new = migrate_service_action.parameter('p_new')
        # ========= PRECONDITIONS =========
        migrate_service_action.add_precondition(self.fluents['migrate_possibility'](h, s, p_old, p_new))
        migrate_service_action.add_precondition(self.fluents['service_active'](h, s))
        migrate_service_action.add_precondition(self.fluents['open_port'](h, p_old))
        migrate_service_action.add_precondition(Not(self.fluents['open_port'](h, p_new)))
        migrate_service_action.add_precondition(self.fluents['service_uses_port'](h, s, p_old))
        migrate_service_action.add_precondition(Not(self.fluents['service_forbidden'](s)))
        migrate_service_action.add_precondition(Not(self.fluents['port_forbidden'](p_new))) 
        # ========= EFFECTS =========
        migrate_service_action.add_effect(self.fluents['open_port'](h, p_new), True)
        migrate_service_action.add_effect(self.fluents['open_port'](h, p_old), False)
        migrate_service_action.add_effect(self.fluents['service_uses_port'](h, s, p_new), True)
        migrate_service_action.add_effect(self.fluents['service_uses_port'](h, s, p_old), False)
        migrate_service_action.add_effect(self.fluents['migrate_possibility'](h, s, p_old, p_new), False)
        return migrate_service_action

    def set_patch_service(self): # this action is needed to patch a service that cannot be mitigated by blocking its ports or migrating it to other ports, for example because it is critical and cannot be disabled, or because there is no possibility to migrate it without causing unacceptable downtime. Patching a service does not cause downtime on it, but it allows to mitigate its vulnerabilities only if the service is not forbidden by company policy (in this case the only option to mitigate it would be disabling it), and if it is not vulnerable to zero-day exploits for which there are no patches available yet (in this case there would be no way to mitigate the service vulnerabilities until patches become available, so the only option would be disabling it until then).
        # ========= INTERFACE =========
        patch_service_action = InstantaneousAction('patch_service', host=self.types['Host'], service=self.types['Service'])
        # ========= PARAMETERS =========
        h = patch_service_action.parameter('host')
        s = patch_service_action.parameter('service')
        # ========= PRECONDITIONS =========
        patch_service_action.add_precondition(self.fluents['service_active'](h, s))
        patch_service_action.add_precondition(self.fluents['service_vulnerable'](h, s))
        patch_service_action.add_precondition(Not(self.fluents['service_forbidden'](s)))
        # ========= EFFECTS =========
        patch_service_action.add_effect(self.fluents['service_vulnerable'](h, s), False)
        return patch_service_action

    def set_reuse_service(self): # this action is needed to reuse a service that has already been mitigated by blocking its ports or migrating it to other ports, for example because it is critical and cannot be disabled, or because there is no possibility to migrate it without causing unacceptable downtime. Reusing a service allows to restore its functionality after it has been mitigated, for example by opening a new port for it and letting it use the new port, but it can be done only if there is an alternative port that can be used by the service (i.e., if there is a port that is not forbidden and that can be opened without affecting other services), so it is not always possible to reuse a service after mitigating it.
        # ========= INTERFACE =========
        reuse_service_action = InstantaneousAction('reuse_service', host=self.types['Host'], service=self.types['Service'], port=self.types['Port'])
        # ========= PARAMETERS =========
        h = reuse_service_action.parameter('host')
        s = reuse_service_action.parameter('service')
        p = reuse_service_action.parameter('port')
        # ========= PRECONDITIONS =========
        reuse_service_action.add_precondition(self.fluents['open_possibility'](p))
        p_using = Variable('p_using', self.types['Port'])
        reuse_service_action.add_precondition(
            Forall(
                Implies(self.fluents['service_uses_port'](h, s, p_using), Not(self.fluents['open_port'](h, p_using))),
                p_using
            )
        )
        # ========= EFFECTS =========
        reuse_service_action.add_effect(self.fluents['service_active'](h, s), True)
        reuse_service_action.add_effect(self.fluents['service_uses_port'](h, s, p), True)
        reuse_service_action.add_effect(self.fluents['open_port'](h, p), True)
        reuse_service_action.add_effect(self.fluents['open_possibility'](p), False)
        return reuse_service_action

    
    def get_problem(self): return self.problem
    def get_types(self): return self.types
    def get_fluents(self): return self.fluents
    def get_actions(self): return self.actions