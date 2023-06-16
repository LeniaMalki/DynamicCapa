from typing import List, Dict, Optional, Set
from collections import defaultdict
import operator
import re

"""
The DynAnal class represents the dynamic behavior of a malware sample.
It tracks and stores information related to API calls, evasive behavior, and process information.
"""
class DynAnal:
    sha256: str
    pidToEvents: Dict[int, List[Dict]]  # Dictionary mapping process ID to a list of dictionaries representing events
    pidToHoneypotEvents: Dict[int, List[Dict]]  # Dictionary mapping process ID to a list of dictionaries representing honeypot events
    orderedEvents: List[Dict]  # List of dictionaries representing events, ordered by time
    evasiveBehaviour: Optional[Dict[str, Set[str]]]  # Optional dictionary representing evasive behavior

    def __init__(self, sha256: str):
        self.sha256 = sha256
        self.pidToEvents = dict()
        self.pidToHoneypotEvents = dict()
        self.orderedEvents = list()
        self.evasiveBehaviour = None

    def sort_events(self):
        self.orderedEvents.sort(key=operator.itemgetter('Time'))  # Sort events based on the 'Time' key

    def get_all_categories(self):
        L = []
        for e in self.orderedEvents:
            if e['Type'] not in L:
                L.append(e['Type'])
        return L
    
    def print_spec_type(self, type):
        for e in self.orderedEvents:
            if e['Type'] == type:
                print(e)
    
    def find_str_in_arg(self, s):
        for e in self.orderedEvents:
            if e['Type'] == 'BEHwA' and e['Cat'] == 'REGISTRY':
                if e['Arg'] != None:
                    if s in e['Arg']:
                        print(e)
                        #print(f"Symbole: {e['Sym']}\tArgument: {e['Arg']}")
    
    def json_registry_match(self, j):
        for e in self.orderedEvents:
            if e['Type'] in j["Registry"]["Type"] and e['Cat'] in j["Registry"]["Cat"] and e['Sym'] in j["Registry"]["Sym"]:
                if e['Arg'] != None and e['Cat'] in j["Registry"]["Cat"]:
                    for arg in j["Registry"]["Arg"]:
                        m = re.search(arg, e['Arg'])
                        if m != None:
                            print(e)
                            print(f"Match rule {j['Id']} ({j['Name']})")
                            print(f"\tSymbole: {e['Sym']}\tArgument: {e['Arg']}")
                            break

    def get_evasive_behaviour(self) -> Dict:
        if self.evasiveBehaviour is not None:
            return self.evasiveBehaviour
        self.evasiveBehaviour = defaultdict(set)  # Create a defaultdict of sets to store evasive behavior
        for e in self.orderedEvents:
            if e['Type'] != 'EVA':
                continue
            self.evasiveBehaviour[e['Cat']].add(e['Title'])  # Add the event title to the corresponding evasive category
        return self.evasiveBehaviour

    def evasion_detected(self) -> bool:
        return len(self.get_evasive_behaviour()) >= 1  # Check if there is at least one evasive behavior detected

    def injection_detected(self) -> bool:
        for pid, events in self.pidToHoneypotEvents.items():
            for e in events:
                if e['Type'] != 'INF':
                    return True  # Return True if an injection event is detected
        return False  # Return False if no injection event is detected

    def is_empty(self) -> bool:
        for event in self.orderedEvents:
            if event['Type'].startswith('BE'):  # Check if an event type starts with 'BE'
                return False  # Return False if there is at least one event of type 'BE'
        return True  # Return True if there are no events of type 'BE'

    def __str__(self):
        return f'sha256={self.sha256}, ' \
               f'nof_processes={len(self.pidToEvents)}, ' \
               f'nof_events={len(self.orderedEvents)}, ' \
               f'injection?{self.injection_detected()}, ' \
               f'evasion?{self.evasion_detected()}'
