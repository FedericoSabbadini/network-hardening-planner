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
        """
        Sets the types for the network hardening problem:
        - Host: represents a host in the network (e.g., a server, a workstation, etc.)
        - Port: represents a port that can be used by a service (e.g., 80, 443, etc.)
        - Service: represents a service that can be active on a host and use one or more ports (e.g., http, ftp, etc.)
        """
        Host = UserType('Host')
        Port = UserType('Port')
        Service = UserType('Service')

        self.types = {'Host': Host, 'Port': Port, 'Service': Service}


    def set_fluents(self):
        """
        Sets the fluents for the network hardening problem:
        - open_port(host, port) = True if port is open on host (i.e., if it is possible for a service to use it), False if the port is closed on host (i.e., if it is not possible for a service to use it, for example because it is blocked by a firewall or because it is already used by another service)
        - service_active(host, service) = True if service on host is active, False if it is disabled (in this case it is not active and not vulnerable)
        - service_critical(host, service) = True if service on host is critical (i.e., if its downtime would cause unacceptable operational impact), False otherwise
        - service_uses_port(host, service, port) = True if service on host uses port, False otherwise (in this case the service does not use the port, so it is not possible to block the port or migrate the service to another port without disabling the service)
        - depends_on(host, dependent_service, base_host, base_service) = True if dependent service on host depends on base_service on base_host (i.e., if downtime of base_service on base_host would cause downtime of dependent_service on host), False otherwise (in this case there is no dependency between the two services, so it is possible to block the port used by base_service or migrate base_service to another port without causing downtime on dependent_service)
        - migrate_possibility(host, service, port_old, port_new) = True if it is possible to migrate service on host from port_old to port_new (i.e., if port_old is a port used by service on host, port_new is an alternative to port_old or a free port, and migrating service from port_old to port_new would not cause unacceptable downtime), False otherwise (in this case it is not possible to migrate the service from port_old to port_new, so the only options to mitigate service vulnerabilities would be disabling or patching it)
        - open_possibility(host, port) = True if it is possible to open port on host (i.e., if port is an alternative to a port used by a service on host or if it is a free port, and opening it would not cause unacceptable downtime), False otherwise (in this case it is not possible to open the port, so the only options to mitigate vulnerabilities of services that could use that port would be disabling or patching them)
        - service_vulnerable(host, service) = True if service on host is vulnerable (i.e., if it has one or more known vulnerabilities that have not been mitigated), False otherwise (in this case the service is not vulnerable, so it does not need mitigation)
        - port_forbidden(port) = True if the port is forbidden by firewall or company policy (e.g., for security reasons), and therefore cannot be used by any service on that host
        - service_forbidden(service) = True if the service is forbidden by company policy (e.g., for security reasons), and therefore cannot be used by any host
        - service_reachable(host, service) = True if service on host is reachable from outside the network (i.e., if it is possible to access it from outside the network, for example because it is using an open port that is not blocked by a firewall), False otherwise (in this case the service is not reachable from outside the network, so it does not need to be mitigated, even if it is vulnerable, because it cannot be accessed by attackers from outside the network)
        """
        open_port = Fluent('open_port', BoolType(), host=self.types['Host'], port=self.types['Port'])
        service_active = Fluent('service_active', BoolType(), host=self.types['Host'], service=self.types['Service']) 
        service_critical = Fluent('service_critical', BoolType(), host=self.types['Host'], service=self.types['Service'])
        service_uses_port = Fluent('service_uses_port', BoolType(), host=self.types['Host'], service=self.types['Service'], port=self.types['Port'])
        depends_on = Fluent('depends_on', BoolType(), host=self.types['Host'], dependent_service=self.types['Service'], base_host=self.types['Host'], base_service=self.types['Service'])
        migrate_possibility = Fluent('migrate_possibility', BoolType(), host=self.types['Host'], service=self.types['Service'], port_old=self.types['Port'], port_new=self.types['Port'])
        open_possibility = Fluent('open_possibility', BoolType(), host=self.types['Host'], port=self.types['Port'])
        service_vulnerable = Fluent('service_vulnerable', BoolType(), host=self.types['Host'], service=self.types['Service'])
        port_forbidden = Fluent('port_forbidden', BoolType(), port=self.types['Port'])
        service_forbidden = Fluent('service_forbidden', BoolType(), service=self.types['Service'])
        service_reachable = Fluent('service_reachable', BoolType(), host=self.types['Host'], service=self.types['Service'])

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
            'service_forbidden': service_forbidden,
            'service_reachable': service_reachable
        }

        for fluent in self.fluents.values():
            self.problem.add_fluent(fluent, default_initial_value=False)


    def set_actions(self):
        """
        Sets the actions for the network hardening problem:
        - disable_service(host, service): disables service on host, making it inactive and not vulnerable (it is not possible to disable a service that is already inactive, or that is reachable from outside the network, or that is vulnerable, because in the first case the service would already be mitigated, in the second case disabling the service would cause unacceptable operational impact, and in the third case it would be risky to disable a vulnerable service without first mitigating the risk of service issues by blocking the port or migrating the service to another port)
        - block_port_firewall(host, port, service): blocks port on host using a firewall, making the service that depends on it unreachable from outside the network (it is not possible to block a port that is not open, or that is used by a critical service, or that is used by a service that is not reachable from outside the network, because in the first case the port would already be blocked, in the second case blocking the port would cause unacceptable operational impact, and in the third case it would not be necessary to block the port because the service is not reachable from outside the network and therefore it does not need mitigation)
        - migrate_service(host, service, port_old, port_new): migrates service on host from port_old to port_new, making it reachable from outside the network through port_new and not reachable from outside the network through port_old (it is not possible to migrate a service that cannot be migrated from port_old to port_new, or that is not active, or that is using a closed port, or that is using a forbidden port, or that is using a forbidden service, or that is not reachable from outside the network, or that is critical, because in the first case the migration would not be possible, in the second case the service would already be mitigated, in the third case it would not be possible to migrate the service because it is using a closed port, in the fourth case it would not be possible to migrate the service because it is using a forbidden port, in the fifth case it would not be possible to migrate the service because it is using a forbidden service, in the sixth case it would not be necessary to migrate the service because it is not reachable from outside the network and therefore it does not need mitigation, and in the seventh case migrating the service would cause unacceptable operational impact)
        - patch_service(host, service, port): patches service on host, making it not vulnerable (it is not possible to patch a service that is using an open port, or that is not active, or that is reachable from outside the network, or that is not vulnerable, or that is using a forbidden service, because in the first case it would be risky to apply a patch that may cause unexpected service issues (e.g., incompatibility, bugs, etc.) without first mitigating the risk of service issues by blocking the port or migrating the service to another port, in the second case the service would already be mitigated, in the third case it would be risky to apply a patch that may cause unexpected service issues (e.g., incompatibility, bugs, etc.) without first mitigating the risk of service issues by blocking the port or migrating the service to another port, in the fourth case the service would already be mitigated, and in the fifth case it would not be possible to patch the service because it is using a forbidden service)
        - reuse_service(host, service, port): reuses port on host for service, making service reachable from outside the network through port (it is not possible to reuse a port for a service if the service is not active, or if it is using an open port, or if it is reachable from outside the network, or if it is using a forbidden service, or if it is using a forbidden port, or if it is critical, or if it is vulnerable, because in the first case the service would already be mitigated, in the second case it would not be possible to reuse the port because it is already open, in the third case it would not be possible to reuse the port because the service is already reachable from outside the network and therefore it does not need mitigation, in the fourth case it would not be possible to reuse the port because it is using a forbidden service, in the fifth case it would not be possible to reuse the port because it is using a forbidden port, in the sixth case reusing the port would cause unacceptable operational impact, and in the seventh case it would be risky to reuse the port without first mitigating the risk of service issues by blocking the port or migrating the service to another port)
         - patch_with_attention(host, service): similar to patch_service, but for critical services, which may require more careful testing and validation before applying the patch, and may have a higher risk of causing unexpected service issues (e.g., incompatibility, bugs, etc.) (it is not possible to patch a critical service that is not active, or that is not vulnerable, or that is using a forbidden service, because in the first case the service would already be mitigated, in the second case the service would already be mitigated, and in the third case it would not be possible to patch the service because it is using a forbidden service)
         - turnoff_safely(host, service, port): similar to disable_service, but for vulnerable services, which may require more careful mitigation to avoid service issues (e.g., incompatibility, bugs, etc.) (it is not possible to turn off a vulnerable service safely if the port it is using cannot be blocked or if there are services that depend on it and would become unreachable from outside the network without it, because in the first case it would be risky to disable the service without first mitigating the risk of service issues by blocking the port, and in the second case it would be risky to disable the service without first mitigating the risk of service issues by blocking the port or migrating the dependent services to other ports) 
        """
        patch_service = self.set_patch_service()
        disable_service = self.set_disable_service()
        migrate_service = self.set_migrate_service()
        reuse_service = self.set_reuse_service()
        block_port = self.set_block_port()
        patch_with_attention = self.set_patch_with_attention()
        turnoff_safely = self.set_turnoff_safely()

        self.actions = {
            'patch_service': patch_service,
            'disable_service': disable_service,
            'migrate_service': migrate_service,
            'reuse_service': reuse_service,
            'block_port': block_port,
            'patch_with_attention': patch_with_attention,
            'turnoff_safely': turnoff_safely
        }

        for action in self.actions.values():
            self.problem.add_action(action)


    def set_disable_service(self): 
        # ========= INTERFACE =========
        disable_service_action = InstantaneousAction('disable_service', host=self.types['Host'], service=self.types['Service'])
        # ========= PARAMETERS =========
        h = disable_service_action.parameter('host')
        s = disable_service_action.parameter('service')
        # ========= PRECONDITIONS =========
        disable_service_action.add_precondition(self.fluents['service_active'](h, s))
        disable_service_action.add_precondition(Not(self.fluents['service_reachable'](h, s)))
        disable_service_action.add_precondition(Not(self.fluents['service_vulnerable'](h, s)))
        # ========= EFFECTS =========
        disable_service_action.add_effect(self.fluents['service_active'](h, s), False)
        return disable_service_action
    

    def set_turnoff_safely(self): 
        # ========= INTERFACE =========
        turnoff_safely_action = InstantaneousAction('turnoff_safely', host=self.types['Host'], service=self.types['Service'], port=self.types['Port'])
        # ========= PARAMETERS =========
        h = turnoff_safely_action.parameter('host')
        s = turnoff_safely_action.parameter('service')
        p = turnoff_safely_action.parameter('port')
        # ========= PRECONDITIONS =========
        turnoff_safely_action.add_precondition(self.fluents['open_port'](h, p))
        turnoff_safely_action.add_precondition(self.fluents['service_uses_port'](h, s, p)) 
        turnoff_safely_action.add_precondition(Not(self.fluents['service_critical'](h, s))) 
        turnoff_safely_action.add_precondition(self.fluents['service_reachable'](h, s))
        turnoff_safely_action.add_precondition(self.fluents['service_active'](h, s))
        h2 = Variable('h2', self.types['Host'])
        s2 = Variable('s2', self.types['Service'])
        turnoff_safely_action.add_precondition(
            Forall(
                Implies(self.fluents['depends_on'](h2, s2, h, s), 
                    Not(self.fluents['service_reachable'](h2, s2))),
                h2, s2
            )
        )
        # ========= EFFECTS =========
        turnoff_safely_action.add_effect(self.fluents['open_port'](h, p), False)
        turnoff_safely_action.add_effect(self.fluents['service_uses_port'](h, s, p), False)
        turnoff_safely_action.add_effect(self.fluents['service_reachable'](h, s), False)
        turnoff_safely_action.add_effect(self.fluents['service_active'](h, s), False)
        turnoff_safely_action.add_effect(self.fluents['service_vulnerable'](h, s), False)
        return turnoff_safely_action
    
    
    def set_block_port(self): 
        # ========= INTERFACE =========
        block_port_action = InstantaneousAction('block_port', host=self.types['Host'], port=self.types['Port'], service=self.types['Service'])
        # ========= PARAMETERS =========
        h = block_port_action.parameter('host')
        p = block_port_action.parameter('port')
        s = block_port_action.parameter('service')
        # ========= PRECONDITIONS =========
        block_port_action.add_precondition(self.fluents['open_port'](h, p))
        block_port_action.add_precondition(self.fluents['service_uses_port'](h, s, p)) 
        block_port_action.add_precondition(Not(self.fluents['service_critical'](h, s))) 
        block_port_action.add_precondition(self.fluents['service_reachable'](h, s))
        block_port_action.add_precondition(self.fluents['service_active'](h, s))
        h2 = Variable('h2', self.types['Host'])
        s2 = Variable('s2', self.types['Service'])
        block_port_action.add_precondition(
            Forall(
                Implies(self.fluents['depends_on'](h2, s2, h, s), 
                    Not(self.fluents['service_reachable'](h2, s2))),
                h2, s2
            )
        )
        # ========= EFFECTS =========
        block_port_action.add_effect(self.fluents['open_port'](h, p), False)
        block_port_action.add_effect(self.fluents['service_uses_port'](h, s, p), False)
        block_port_action.add_effect(self.fluents['service_reachable'](h, s), False)
        return block_port_action
        
    
    def set_migrate_service(self): 
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
        migrate_service_action.add_precondition(self.fluents['service_reachable'](h, s))
        migrate_service_action.add_precondition(Not(self.fluents['service_critical'](h, s)))
        # ========= EFFECTS =========
        migrate_service_action.add_effect(self.fluents['open_port'](h, p_new), True)
        migrate_service_action.add_effect(self.fluents['open_port'](h, p_old), False)
        migrate_service_action.add_effect(self.fluents['service_uses_port'](h, s, p_new), True)
        migrate_service_action.add_effect(self.fluents['service_uses_port'](h, s, p_old), False)
        migrate_service_action.add_effect(self.fluents['migrate_possibility'](h, s, p_old, p_new), False)
        migrate_service_action.add_effect(self.fluents['service_reachable'](h, s), True)
        return migrate_service_action

    
    def set_patch_service(self):
        # ========= INTERFACE =========
        patch_service_action = InstantaneousAction('patch_service', host=self.types['Host'], service=self.types['Service'], port=self.types['Port'])
        # ========= PARAMETERS =========
        h = patch_service_action.parameter('host')
        s = patch_service_action.parameter('service')
        p = patch_service_action.parameter('port')
        # ========= PRECONDITIONS =========
        patch_service_action.add_precondition(Not(self.fluents['open_port'](h, p)))  # patching can be done only if the service is not using an open port, because if the service is using an open port it would be reachable from outside the network and therefore it would be risky to apply a patch that may cause unexpected service issues (e.g., incompatibility, bugs, etc.) without first mitigating the risk of service issues by blocking the port or migrating the service to another port
        patch_service_action.add_precondition(self.fluents['service_active'](h, s))
        patch_service_action.add_precondition(Not(self.fluents['service_reachable'](h, s)))
        patch_service_action.add_precondition(self.fluents['service_vulnerable'](h, s))
        patch_service_action.add_precondition(Not(self.fluents['service_forbidden'](s)))
        # ========= EFFECTS =========
        patch_service_action.add_effect(self.fluents['service_vulnerable'](h, s), False)
        patch_service_action.add_effect(self.fluents['open_port'](h, p), True)
        patch_service_action.add_effect(self.fluents['service_uses_port'](h, s, p), True)
        patch_service_action.add_effect(self.fluents['service_reachable'](h, s), True)
        return patch_service_action
    
    def set_patch_with_attention(self):
        # ========= INTERFACE =========
        patch_with_attention_action = InstantaneousAction('patch_with_attention', host=self.types['Host'], service=self.types['Service'])
        # ========= PARAMETERS =========
        h = patch_with_attention_action.parameter('host')
        s = patch_with_attention_action.parameter('service')
        # ========= PRECONDITIONS =========
        patch_with_attention_action.add_precondition(self.fluents['service_active'](h, s))
        patch_with_attention_action.add_precondition(self.fluents['service_vulnerable'](h, s))
        patch_with_attention_action.add_precondition(Not(self.fluents['service_forbidden'](s)))
        patch_with_attention_action.add_precondition(self.fluents['service_critical'](h, s))
        # ========= EFFECTS =========
        patch_with_attention_action.add_effect(self.fluents['service_vulnerable'](h, s), False)
        return patch_with_attention_action

    def set_reuse_service(self): 
        # ========= INTERFACE =========
        reuse_service_action = InstantaneousAction('reuse_service', host=self.types['Host'], service=self.types['Service'], port=self.types['Port'])
        # ========= PARAMETERS =========
        h = reuse_service_action.parameter('host')
        s = reuse_service_action.parameter('service')
        p = reuse_service_action.parameter('port')
        # ========= PRECONDITIONS =========
        reuse_service_action.add_precondition(self.fluents['service_active'](h, s))
        reuse_service_action.add_precondition(self.fluents['open_possibility'](h, p))
        reuse_service_action.add_precondition(Not(self.fluents['service_forbidden'](s)))
        reuse_service_action.add_precondition(Not(self.fluents['open_port'](h, p)))
        reuse_service_action.add_precondition(Not(self.fluents['service_reachable'](h, s)))
        reuse_service_action.add_precondition(Not(self.fluents['port_forbidden'](p)))
        reuse_service_action.add_precondition(Not(self.fluents['service_critical'](h, s)))
        reuse_service_action.add_precondition(Not(self.fluents['service_vulnerable'](h, s)))
        # ========= EFFECTS =========
        reuse_service_action.add_effect(self.fluents['service_uses_port'](h, s, p), True)
        reuse_service_action.add_effect(self.fluents['open_port'](h, p), True)
        reuse_service_action.add_effect(self.fluents['open_possibility'](h, p), False)
        reuse_service_action.add_effect(self.fluents['service_reachable'](h, s), True)
        return reuse_service_action
    

    def get_problem(self): return self.problem
    def get_types(self): return self.types
    def get_fluents(self): return self.fluents
    def get_actions(self): return self.actions