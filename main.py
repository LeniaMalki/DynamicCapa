import os
import pickle
from classes import DynAnal
import json

def print_INF_tree(d):
    print("Type: INF (information)")
    print(f"Key list: {list(d['KEY LIST'])}")
    print("- (Title)")
    print("\t- (Desc)")
    for t in d.keys():
        if t != 'KEY LIST':
            print(f"- {t}")
            print(f"\t- {d[t]}")

def print_BEH_tree(d):
    print("Type: BEH (Behaviour)")
    print(f"Key list: {list(d['KEY LIST'])}")
    print("- <Cat>")
    print("\t- <Sym>")
    for c in d.keys():
        if c != 'KEY LIST':
            print(f"- {c}")
            for s in d[c]:
                print(f"\t- {s}")

def print_BEHwA_tree(d):
    print("Type: BEHwA (Behaviour)")
    print(f"Key list: {list(d['KEY LIST'])}")
    print("- <Cat>")
    print("\t- <Sym> (<Arg>)")
    for c in d.keys():
        if c != 'KEY LIST' and ' Arg' not in c:
            print(f"- {c}")
            for (s, a) in zip(d[c], d[c+' Arg']):
                print(f"\t- {s} ({a})")

def load_pickle_file(file_path):
    with open(file_path, 'rb') as f:
        dynanal = pickle.load(f)
    return dynanal

def extract_information(dynanal):
    # Extract API calls
    api_calls = dynanal.orderedEvents
    # Extract evasive behavior
    evasive_behavior = dynanal.get_evasive_behaviour()
    
    # Extract process information
    process_info = {
        'pidToEvents': dynanal.pidToEvents,
        'pidToHoneypotEvents': dynanal.pidToHoneypotEvents
    }
    
    return api_calls, evasive_behavior, process_info

def print_api_calls(api_calls):
    for a in api_calls:
        print(a)
    print("########################")

def print_evasive_behaviour(evasive_behaviour):
    for category, titles in evasive_behaviour.items():
        print(f"Evasive Category: {category}")
        for title in titles:
            print(f"    Title: {title}")
    print("########################")

def print_process_info(process_info):
    print("Process IDs from pidToEvents:", list(process_info['pidToEvents'].keys()))
    print("Process IDs from honeypotEvents:", list(process_info['pidToHoneypotEvents'].keys()))
    print("########################")

def print_report(r, name=None):
    print(f"Report for {name}")
    for k in r.keys():
        d = r[k]
        l = f"{len(d)} {k} technique(s): "
        for j in d:
            l = l + f"{j}, "
        print(l[:-2])

def apply_rule(dynanal, j, r):
    if "Registry" in j.keys():
        m = dynanal.json_registry_match(j)
        if m:
            for cat in j['Tactics']:
                r[cat].add(j['Id'])
    if "Process" in j.keys():
        m = dynanal.json_process_match(j)
        if m:
            for cat in j['Tactics']:
                r[cat].add(j['Id'])
    if "Filesystem" in j.keys():
        m = dynanal.json_file_match(j)
        if m:
            for cat in j['Tactics']:
                r[cat].add(j['Id'])


def init_result_dictionnary():
    r = {
        "Reconnaissance": set(),
        "Resource Development": set(),
        "Initial access": set(),
        "Execution": set(),
        "Persistence": set(),
        "Privilege Escalation": set(),
        "Defense Evasion": set(),
        "Credential Access": set(),
        "Discovery": set(),
        "Lateral Movement": set(),
        "Collection": set(),
        "Command and Control": set(),
        "Exfiltration": set(),
        "Impact": set()
    }
    return r

# Example usage
pickles_folder = 'pickles_folder'

def analyze_malware_samples(pickles_folder):
    rules = []
    for json_f in os.listdir('json'):
        with open(os.path.join('json', json_f)) as f:
            rules.append(json.load(f))
    print(f"{len(rules)} rule(s) loaded")
    for directory in os.listdir(pickles_folder):
        print("########################")
        print(directory)
        print("########################")
        r = init_result_dictionnary()
        for filename in os.listdir(os.path.join(pickles_folder, directory)):
            file_path = os.path.join(pickles_folder, directory, filename)
            dynanal = load_pickle_file(file_path)
            #api_calls, evasive_behavior, process_info = extract_information(dynanal)
            #dynanal.print_spec_type(['BEHwA'])
            
                #print(json_f)
            for j in rules:
                #dynanal.json_registry_match(j)
                apply_rule(dynanal, j, r)
        print_report(r, name=directory)

            
            #dynanal.get_INF_tree(d)
            #dynanal.get_BEHwA_tree(d)
            #with open('json/T1003_004.json') as f:
            #    dynanal.json_registry_match(json.load(f))
            #'''print_api_calls(api_calls)
            #print_evasive_behaviour(evasive_behavior)
            #print_process_info(process_info)
            #print("\n")
            #'''
            #L = L + dynanal.get_all_categories()
            #break # Set to only process 1 .pickle atm
    #print("Categories:")
    #L = list(dict.fromkeys(L))
    #for t in L:
        #print(f"\t- {t}")
    #print_INF_tree(d)
    #print_BEHwA_tree(d)

analyze_malware_samples(pickles_folder)
