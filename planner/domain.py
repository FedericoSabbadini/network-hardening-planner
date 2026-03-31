from unified_planning.shortcuts import Problem, UserType, Fluent, BoolType

class NetworkHardeningDomain:
    """
    Definisce il DOMINIO di planning per il network hardening.

    Un dominio specifica:
    - I TIPI di oggetti che esistono nel mondo
    - I FLUENT (predicati) che descrivono lo stato
    """

    def __init__(self):
        # Crea un nuovo problema di planning
        self.problem = Problem('network_hardening')

        # === DEFINIZIONE DEI TIPI ===
        # I tipi definiscono le "categorie" di oggetti nel nostro mondo
        Host = UserType('Host')       # Un server o macchina nella rete
        Port = UserType('Port')       # Una porta di rete (es. 80, 443, 22)
        Service = UserType('Service') # Un servizio software (es. http, mysql)

        # === DEFINIZIONE DEI FLUENT ===
        # I fluent sono "variabili" che descrivono lo stato del mondo
        # Sono tutti booleani: vero o falso

        self.fluents = {
            # porta_aperta(host, port) = True se la porta è aperta sull'host
            'porta_aperta': Fluent('porta_aperta', BoolType(), host=Host, port=Port),

            # servizio_attivo(host, service) = True se il servizio è in esecuzione
            'servizio_attivo': Fluent('servizio_attivo', BoolType(), host=Host, service=Service),

            # servizio_critico(host, service) = True se il servizio NON può essere fermato
            'servizio_critico': Fluent('servizio_critico', BoolType(), host=Host, service=Service),

            # servizio_usa_porta(host, service, port) = True se il servizio usa quella porta
            'servizio_usa_porta': Fluent('servizio_usa_porta', BoolType(),
                                         host=Host, service=Service, port=Port),

            # dipende_da(host, srv_A, srv_B) = True se srv_A dipende da srv_B
            # Esempio: se 'http' dipende da 'mysql', non posso fermare mysql prima di http
            'dipende_da': Fluent('dipende_da', BoolType(),
                                host=Host, service_dipendente=Service, service_base=Service)
        }

        # Aggiungi tutti i fluent al problema
        # default_initial_value=False significa che di default tutto è "falso"
        # (le porte sono chiuse, i servizi sono inattivi, etc.)
        for fluent in self.fluents.values():
            self.problem.add_fluent(fluent, default_initial_value=False)

        # Salva i tipi per uso successivo
        self.types = {'Host': Host, 'Port': Port, 'Service': Service}