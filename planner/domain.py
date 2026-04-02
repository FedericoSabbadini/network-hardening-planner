from unified_planning.shortcuts import Problem, UserType, Fluent, BoolType, InstantaneousAction, Variable, Forall, Implies, Not, And


class NetworkHardeningDomain:
    """
    Domain class for the network hardening problem.

    Types: Host, Port, Service
    Fluents: open_port, service_active, service_critical, service_uses_port,
             depends_on(host, dependent_service, base_host, base_service),  ← cross-host
             migrate_possibility, service_vulnerable
    Actions: disable_service, block_port_firewall, migrate_service, patch_service
    """

    def __init__(self):

        self.problem = Problem('network_hardening')

        # ========= TYPES =========
        Host = UserType('Host')
        Port = UserType('Port')
        Service = UserType('Service')
        self.types = {'Host': Host, 'Port': Port, 'Service': Service}

        # ========= FLUENTS =========
        open_port = Fluent('open_port', BoolType(), host=Host, port=Port)
        service_active = Fluent('service_active', BoolType(), host=Host, service=Service)
        service_critical = Fluent('service_critical', BoolType(), host=Host, service=Service)
        service_uses_port = Fluent('service_uses_port', BoolType(), host=Host, service=Service, port=Port)

        # FIX 3: depends_on ora è cross-host — aggiunto base_host
        depends_on = Fluent('depends_on', BoolType(),
                            host=Host, dependent_service=Service,
                            base_host=Host, base_service=Service)

        migrate_possibility = Fluent('migrate_possibility', BoolType(),
                                     host=Host, service=Service, port_old=Port, port_new=Port)
        service_vulnerable = Fluent('service_vulnerable', BoolType(), host=Host, service=Service)

        port_forbidden = Fluent('port_forbidden', BoolType(), port=Port) # port_forbidden(port) = True se la porta è proibita da firewall o policy aziendale (es. per motivi di sicurezza), e quindi non può essere usata da nessun servizio su quel host
        service_forbidden = Fluent('service_forbidden', BoolType(), service=Service) # service_forbidden(service) = True se il servizio è proibito da

        self.fluents = {
            'open_port': open_port,
            'service_active': service_active,
            'service_critical': service_critical,
            'service_uses_port': service_uses_port,
            'depends_on': depends_on,
            'migrate_possibility': migrate_possibility,
            'service_vulnerable': service_vulnerable,
            'port_forbidden': port_forbidden,
            'service_forbidden': service_forbidden
        }
        for fluent in self.fluents.values():
            self.problem.add_fluent(fluent, default_initial_value=False)

        # ========= ACTIONS =========

        # ------ 1. disable_service(host, service) ------
        disable_service_action = InstantaneousAction('disable_service', host=Host, service=Service)
        h = disable_service_action.parameter('host')
        s = disable_service_action.parameter('service')

        disable_service_action.add_precondition(service_active(h, s))

        # La porta di s deve essere già chiusa prima di disabilitare
        p = Variable('p', Port)
        disable_service_action.add_precondition(
            Forall(
                Implies(service_uses_port(h, s, p), 
                Not(open_port(h, p))),
                p
            )
        )

        # Effects
        disable_service_action.add_effect(service_active(h, s), False)
        disable_service_action.add_effect(service_vulnerable(h, s), False)  # patching è implicito nella disabilitazione


        # ------ 2. block_port_firewall(host, port, service) ------
        block_port_firewall_action = InstantaneousAction('block_port_firewall', host=Host, port=Port, service=Service)
        h = block_port_firewall_action.parameter('host')
        p = block_port_firewall_action.parameter('port')
        s = block_port_firewall_action.parameter('service')

        # non deve essere possibile fare una migrazione su un'altra porta NON FORBIDDEN per il servizio s NON FORBIDDEN, altrimenti sarebbe preferibile migrare invece di bloccare la porta
        p_mig = Variable('p_mig', Port)
        block_port_firewall_action.add_precondition(
            Forall(
                Implies(migrate_possibility(h, s, p, p_mig),
                Not(And(Not(port_forbidden(p_mig)), Not(service_forbidden(s))))),
                p_mig
            )
        )

        block_port_firewall_action.add_precondition(open_port(h, p))
        block_port_firewall_action.add_precondition(service_uses_port(h, s, p)) 
        block_port_firewall_action.add_precondition(Not(service_critical(h, s))) # il servizio che usa la porta non deve essere critico (altrimenti bloccare la porta causerebbe un downtime critico
        
        # se esiste un h2 e un s2 su esso, non deve essere possibile che depends_on(h2, s2, h, s) sia True, altrimenti bloccare la porta causerebbe un downtime su s2 che dipende da s
        h2 = Variable('h2', Host)
        s2 = Variable('s2', Service)
        block_port_firewall_action.add_precondition(
            Forall(
                Implies(depends_on(h2, s2, h, s), 
                Not(service_active(h2, s2))),
                h2, s2
            )
        )
        
        block_port_firewall_action.add_effect(open_port(h, p), False)
        block_port_firewall_action.add_effect(service_uses_port(h, s, p), False)

        # ------ 3. migrate_service(h, s, p_old, p_new) ------
        migrate_service_action = InstantaneousAction('migrate_service', h=Host, s=Service, p_old=Port, p_new=Port)
        h = migrate_service_action.parameter('h')
        s = migrate_service_action.parameter('s')
        p_old = migrate_service_action.parameter('p_old')
        p_new = migrate_service_action.parameter('p_new')

        migrate_service_action.add_precondition(migrate_possibility(h, s, p_old, p_new))
        migrate_service_action.add_precondition(service_active(h, s))
        migrate_service_action.add_precondition(open_port(h, p_old))
        migrate_service_action.add_precondition(Not(open_port(h, p_new)))
        migrate_service_action.add_precondition(service_uses_port(h, s, p_old))
        migrate_service_action.add_precondition(Not(service_forbidden(s))) # il servizio non deve essere proibito da policy aziendale (es. per motivi di sicurezza), se è proibito deve essere disabilitato invece che migrato
        migrate_service_action.add_precondition(Not(port_forbidden(p_new))) # la nuova porta non deve essere proibita da policy aziendale (es. per motivi di sicurezza), se è proibita deve essere bloccata invece che usata per migrare

        migrate_service_action.add_effect(open_port(h, p_new), True)
        migrate_service_action.add_effect(open_port(h, p_old), False)
        migrate_service_action.add_effect(service_uses_port(h, s, p_new), True)
        migrate_service_action.add_effect(service_uses_port(h, s, p_old), False)
        migrate_service_action.add_effect(migrate_possibility(h, s, p_old, p_new), False)


        # ------ 4. patch_service(host, service) ------
        patch_service_action = InstantaneousAction('patch_service', host=Host, service=Service)
        h = patch_service_action.parameter('host')
        s = patch_service_action.parameter('service')

        patch_service_action.add_precondition(service_active(h, s))
        patch_service_action.add_precondition(service_vulnerable(h, s))
        patch_service_action.add_precondition(Not(service_forbidden(s))) # il servizio non deve essere proibito da policy aziendale (es. per motivi di sicurezza, se è vulnerabile non può essere patchato ma deve essere disabilitato o migrato)

        patch_service_action.add_effect(service_vulnerable(h, s), False)


        self.actions = {
            'patch_service': patch_service_action, 
            'disable_service': disable_service_action,
            'migrate_service': migrate_service_action,
            'block_port_firewall': block_port_firewall_action,
        }
        for action in self.actions.values():
            self.problem.add_action(action)

    def get_problem(self): return self.problem
    def get_types(self): return self.types
    def get_fluents(self): return self.fluents
    def get_actions(self): return self.actions