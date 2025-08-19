import json
from stix2 import MemoryStore, Filter

# Load the MITRE ATT&CK STIX data
with open('../Output/enterprise-attack.json') as f:
    enterprise_attack_data = json.load(f)

# Create an in-memory STIX data store
memory_store = MemoryStore(stix_data=enterprise_attack_data['objects'])

# Filter to get all techniques
techniques = memory_store.query([
    Filter('type', '=', 'attack-pattern')
])

# Create a dictionary to map techniques to tactics
technique_to_tactic = {}

# Iterate over each technique
for technique in techniques:
    # Get the technique ID and name
    technique_id = technique.get('external_references', [{}])[0].get('external_id', '')
    technique_name = technique.get('name', '')

    # Get the kill chain phases (tactics)
    kill_chain_phases = technique.get('kill_chain_phases', [])
    for phase in kill_chain_phases:
        tactic = phase.get('phase_name', '')
        if technique_id:
            if technique_id not in technique_to_tactic:
                technique_to_tactic[technique_id] = []
            technique_to_tactic[technique_id].append(tactic)

def get_technique_to_tactic():
    return technique_to_tactic
