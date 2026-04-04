from unified_planning.shortcuts import Problem, UserType, Fluent, BoolType, InstantaneousAction, Variable, Forall, Implies, Not


class NetworkHardeningDomain:
    """
    Domain class for the network hardening problem.

    Types: Host, Port, Service
    Fluents: open_port(host, port), service_active(host, service), 
    service_critical(host, service), service_uses_port(host, service, port), 
    depends_on(host, dependent_service, base_host, base_service), migrate_possibility(host, service, port_old, port_new), 
    open_possibility(host, port), service_vulnerable(host, service), port_forbidden(port), 
    service_forbidden(service), service_reachable(host, service)
    Actions: disable_service(host, service), block_port(host, port, service),
      migrate_service(host, service, port_old, port_new), patch_service(host, service), 
      open_new_port(host, port, service), restore_service(host, service, port), block_for_maintenance(host, port, service)
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
        service_used_port = Fluent('service_used_ports', BoolType(), host=self.types['Host'], service=self.types['Service'], ports=self.types['Port'])  # auxiliary fluent to represent the set of ports used by a service on a host, which can be used to define the preconditions of actions that require checking if a service is using a port or if it is possible to migrate a service from one port to another
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
            'service_used_port': service_used_port,
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
        - disable_service(host, service): disables service on host, making it inactive and not vulnerable, and making it not reachable from outside the network (because it is not active), with low operational impact (because the service is disabled but not removed, so it can be easily re-enabled if needed) and low risk during the operation (because disabling a service is a simple operation that is less likely to cause unexpected issues than blocking a port or migrating a service to another port)
        - block_port(host, port, service): blocks port on host, making it not open and not usable by the service, and making the service not reachable from outside the network (because it is using a blocked port), with high operational impact (because blocking a port makes the service that depends on it unavailable from outside, which may cause significant disruption to users or customers) and high risk during the operation (because blocking a port may cause unexpected service issues, for example if the service is using that port for internal communication or if it is not properly configured to handle the case where the port is blocked)
        - migrate_service(host, service, port_old, port_new): migrates service on host from port_old to port_new, making it use port_new instead of port_old, and making it reachable from outside the network (because it is using an open port that is not blocked by a firewall), with high operational impact (because migrating a service to another port may require downtime to apply the migration, and may cause significant disruption to users or customers) and high risk during the operation (because migrating a service to another port may cause unexpected service issues, for example if the service is not properly configured to use the new port or if there are compatibility issues with the new port)
        - patch_service(host, service): patches service on host, making it not vulnerable, with low operational impact (because patching a service does not make it unavailable, so it does not cause disruption to users or customers) and medium risk during the operation (because there is a risk the patch may cause unexpected service issues, for example if the patch is not properly tested or if it introduces new vulnerabilities)
        - open_new_port(host, port, service): opens port on host and makes service use it, making the service reachable from outside the network (because it is using an open port that is not blocked by a firewall), with high operational impact (because opening a new port and making a service use it may require downtime to apply the changes, and may cause significant disruption to users or customers) and high risk during the operation (because opening a new port and making a service use it may cause unexpected service issues, for example if the service is not properly configured to use the new port or if there are compatibility issues with the new port)
        - restore_service(host, service, port): restores service on host by reopening the port it uses, making the service reachable from outside the network (because it is using an open port that is not blocked by a firewall), with low operational impact (because restoring a service by reopening the port it uses may require some downtime to apply the changes, but it does not cause disruption to users or customers because it restores the service to its previous state) and medium risk during the operation (because there is a risk that restoring a service by reopening the port it uses may cause unexpected service issues, for example if there are other services that depend on it or if it is not properly configured to handle the case where the port is reopened)
        - block_for_maintenance(host, port, service): blocks port on host for maintenance, making it not open and not usable by the service, and making the service not reachable from outside the network (because it is using a blocked port), with medium operational impact (because blocking a port for maintenance is a temporary measure that is planned and communicated in advance, so it causes less disruption to users or customers than an unplanned port block) and medium risk during the operation (because blocking a port for maintenance is a planned operation that is less likely to cause unexpected issues than an unplanned port block, but there is still a risk of service issues if the maintenance is not properly planned or executed)
        """
        patch_service = self.set_patch_service()
        disable_service = self.set_disable_service()
        migrate_service = self.set_migrate_service()
        open_new_port = self.set_open_new_port()
        block_port = self.set_block_port()
        restore_service = self.set_restore_service()
        block_for_manteanance = self.set_block_for_maintenance()

        self.actions = {
            'patch_service': patch_service,
            'disable_service': disable_service,
            'migrate_service': migrate_service,
            'open_new_port': open_new_port,
            'block_port': block_port,
            'restore_service': restore_service,
            'block_for_maintenance': block_for_manteanance

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
        disable_service_action.add_precondition(Not(self.fluents['service_critical'](h, s))) 
        # ========= EFFECTS =========
        disable_service_action.add_effect(self.fluents['service_active'](h, s), False)
        return disable_service_action
    
    
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
        

    def set_block_for_maintenance(self):
        action = InstantaneousAction(
            'block_for_maintenance',
            host=self.types['Host'], port=self.types['Port'], service=self.types['Service']
        )
        h = action.parameter('host')
        p = action.parameter('port')
        s = action.parameter('service')

        # --- PRECONDITIONS ---
        action.add_precondition(self.fluents['open_port'](h, p))
        action.add_precondition(self.fluents['service_uses_port'](h, s, p))
        action.add_precondition(self.fluents['service_reachable'](h, s))
        action.add_precondition(self.fluents['service_active'](h, s))
        action.add_precondition(self.fluents['service_vulnerable'](h, s))       

        # --- EFFECTS ---
        action.add_effect(self.fluents['open_port'](h, p), False)
        action.add_effect(self.fluents['service_uses_port'](h, s, p), False)
        action.add_effect(self.fluents['service_used_port'](h, s, p), True)    
        action.add_effect(self.fluents['service_reachable'](h, s), False)
        return action


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
        migrate_service_action.add_effect(self.fluents['service_used_port'](h, s, p_old), True)
        return migrate_service_action

    
    def set_restore_service(self):
        # ========= INTERFACE =========
        restore_service_action = InstantaneousAction('restore_service', host=self.types['Host'], port=self.types['Port'], service=self.types['Service'])
        # ========= PARAMETERS =========
        h = restore_service_action.parameter('host')
        s = restore_service_action.parameter('service')
        p = restore_service_action.parameter('port')
        # ========= PRECONDITIONS =========
        restore_service_action.add_precondition(Not(self.fluents['open_port'](h, p))) 
        restore_service_action.add_precondition(self.fluents['service_active'](h, s))
        restore_service_action.add_precondition(Not(self.fluents['service_reachable'](h, s)))
        restore_service_action.add_precondition(Not(self.fluents['service_forbidden'](s)))
        restore_service_action.add_precondition(Not(self.fluents['port_forbidden'](p)))
        restore_service_action.add_precondition(self.fluents['service_used_port'](h, s, p)) 
        restore_service_action.add_precondition(Not(self.fluents['service_vulnerable'](h, s)))
        # ========= EFFECTS =========
        restore_service_action.add_effect(self.fluents['open_port'](h, p), True)
        restore_service_action.add_effect(self.fluents['service_uses_port'](h, s, p), True)
        restore_service_action.add_effect(self.fluents['service_reachable'](h, s), True)
        restore_service_action.add_effect(self.fluents['service_used_port'](h, s, p), False)
        return restore_service_action


    def set_patch_service(self):
        # ========= INTERFACE =========
        patch_service_action = InstantaneousAction('patch_service', host=self.types['Host'], service=self.types['Service'])
        # ========= PARAMETERS =========
        h = patch_service_action.parameter('host')
        s = patch_service_action.parameter('service')
        # ========= PRECONDITIONS =========
        patch_service_action.add_precondition(self.fluents['service_active'](h, s))
        patch_service_action.add_precondition(self.fluents['service_vulnerable'](h, s))
        patch_service_action.add_precondition(Not(self.fluents['service_reachable'](h, s)))  
        # ========= EFFECTS =========
        patch_service_action.add_effect(self.fluents['service_vulnerable'](h, s), False)
        return patch_service_action


    def set_open_new_port(self):
        # ========= INTERFACE =========
        open_new_port_action = InstantaneousAction('open_new_port', host=self.types['Host'], port=self.types['Port'], service=self.types['Service'])
        # ========= PARAMETERS =========
        h = open_new_port_action.parameter('host')
        s = open_new_port_action.parameter('service')
        p = open_new_port_action.parameter('port')
        # ========= PRECONDITIONS =========
        open_new_port_action.add_precondition(self.fluents['service_active'](h, s))
        open_new_port_action.add_precondition(self.fluents['open_possibility'](h, p))
        open_new_port_action.add_precondition(Not(self.fluents['service_forbidden'](s)))
        open_new_port_action.add_precondition(Not(self.fluents['open_port'](h, p)))
        open_new_port_action.add_precondition(Not(self.fluents['service_reachable'](h, s)))
        open_new_port_action.add_precondition(Not(self.fluents['service_critical'](h, s)))
        open_new_port_action.add_precondition(Not(self.fluents['service_vulnerable'](h, s)))
        open_new_port_action.add_precondition(Not(self.fluents['port_forbidden'](p)))

        # ========= EFFECTS =========
        open_new_port_action.add_effect(self.fluents['service_uses_port'](h, s, p), True)
        open_new_port_action.add_effect(self.fluents['open_port'](h, p), True)
        open_new_port_action.add_effect(self.fluents['open_possibility'](h, p), False)
        open_new_port_action.add_effect(self.fluents['service_reachable'](h, s), True)
        return open_new_port_action
    

    def get_problem(self): return self.problem
    def get_types(self): return self.types
    def get_fluents(self): return self.fluents
    def get_actions(self): return self.actions