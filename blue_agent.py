# blue_agent.py
from pgmpy.models import DiscreteBayesianNetwork
from pgmpy.factors.discrete import TabularCPD
from pgmpy.inference import VariableElimination

class SentinelBayesianBrain:
    def __init__(self):
        self.model = DiscreteBayesianNetwork([
            ('PortScan', 'Compromised'), 
            ('FailedLogin', 'Compromised')
        ])

        cpd_port_scan = TabularCPD(variable='PortScan', variable_card=2, values=[[0.9], [0.1]])
        cpd_failed_login = TabularCPD(variable='FailedLogin', variable_card=2, values=[[0.95], [0.05]])

        cpd_compromised = TabularCPD(
            variable='Compromised', 
            variable_card=2, 
            values=[
                [0.999, 0.70, 0.60, 0.05], 
                [0.001, 0.30, 0.40, 0.95]  
            ],
            evidence=['PortScan', 'FailedLogin'],
            evidence_card=[2, 2]
        )

        self.model.add_cpds(cpd_port_scan, cpd_failed_login, cpd_compromised)
        self.model.check_model()
        self.inference = VariableElimination(self.model)

    def calculate_threat_probability(self, scan_detected: int, login_spike: int) -> float:
        result = self.inference.query(
            variables=['Compromised'], 
            evidence={'PortScan': scan_detected, 'FailedLogin': login_spike},
            show_progress=False
        )
        return result.values[1]

def get_blue_agent_action(observation_dict, bayesian_brain):
    """
    Evaluates the graph and returns a defensive action.
    """
    graph = observation_dict['graph']
    
    for node, attributes in graph.nodes(data=True):
        if attributes.get('status') == 'isolated':
            continue
            
        # In a real run, these come from engine telemetry.
        # For this test, we simulate an alert if the node is actively compromised.
        has_scan = 1 if attributes.get('status') == 'compromised' else 0
        has_fail = 1 if attributes.get('status') == 'compromised' else 0
        
        if has_scan or has_fail:
            threat_prob = bayesian_brain.calculate_threat_probability(has_scan, has_fail)
            print(f"  [AI] Node {node} threat probability calculated at {threat_prob:.2%}")
            
            # Confidence Threshold
            if threat_prob > 0.80:
                print(f"  [AI] --> Threshold exceeded. Initiating isolation for {node}.")
                return ("isolate", node)
                
    return ("sleep", None)