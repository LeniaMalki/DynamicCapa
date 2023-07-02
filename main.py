import os
import pickle
import json
import csv
import pandas as pd
import time


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

# Function to extract information from the loaded pickle file
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


# Function to print API calls
def print_api_calls(api_calls):
    for a in api_calls:
        print(a)

# Function to print evasive behavior
def print_evasive_behaviour(evasive_behaviour):
    for category, titles in evasive_behaviour.items():
        print(f"Evasive Category: {category}")
        for title in titles:
            print(f"    Title: {title}")

# Function to print process information
def print_process_info(process_info):
    print("Process IDs from pidToEvents:", list(
        process_info['pidToEvents'].keys()))
    print("Process IDs from honeypotEvents:", list(
        process_info['pidToHoneypotEvents'].keys()))

# Folder for storing reports
reports_folder = "reports"
# Create a unique scan time based on the current timestamp
scan_time = str(int(time.time()))

if not os.path.exists(reports_folder):
    os.makedirs(reports_folder)


def create_report(results, name):
    file_path = os.path.join(reports_folder, f"{name}_summary_{scan_time}.csv")
    with open(file_path, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Technique", "Count", "IDs"])
        for technique, techniques_set in results.items():
            print(techniques_set)
            count = len(techniques_set)
            ids = ', '.join(techniques_set)
            writer.writerow([technique, count, ids])

    display_report_dataframe(file_path)

# Function to apply a rule to the results
def apply_rule(dynanal, j, r, rule_set):
    rule_set[j["Id"]] = j["Name"]
    if j.get("Registry"):
        match = dynanal.json_registry_match(j)
        if match:
            for cat in j['Tactics']:
                r[cat].add(j['Id'])

    if j.get("Process"):
        match = dynanal.json_process_match(j)
        if match:
            for cat in j['Tactics']:
                r[cat].add(j['Id'])
    if j.get("Filesystem"):
        match = dynanal.json_file_match(j)
        if match:
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


def load_json_files():
    rules = []
    for json_f in os.listdir('json'):
        with open(os.path.join('json', json_f)) as f:
            rules.append(json.load(f))
    # print(f"{len(rules)} rule(s) loaded")
    return rules


def print_result_dict(result_dict):
    for key, value in result_dict.items():
        print(f"{key}: {value}")


def display_report_dataframe(file_path):
    df = pd.read_csv(file_path)
    print(df)


def save_detailed_report(r, rule_set, name):
    with open(os.path.join(reports_folder, f"{name}_report_{scan_time}.txt"), 'w', encoding="utf-8") as rep:
        rep.write(f"Detailed report for {name}\n\n")
        for k in r.keys():
            rep.write("#"*30 + '\n')
            rep.write(f"Category: {k}\n")
            rep.write("#"*30 + '\n')
            d = r[k]
            for id in d:
                t_name = rule_set[id]
                rep.write(f"Technique ID: {id}\n")
                rep.write(f"Technique Name: {t_name}\n")
                rep.write("-"*30 + '\n')
            rep.write('\n')


def analyze_malware_samples(pickles_folder):
    rules = load_json_files()
    rule_set = {}
    for directory in os.listdir(pickles_folder):
        result_dict = init_result_dictionnary()
        print("___Directory", directory, "____")

        for filename in os.listdir(os.path.join(pickles_folder, directory)):
            file_path = os.path.join(pickles_folder, directory, filename)
            trace_file = load_pickle_file(file_path)

            for rule in rules:
                apply_rule(trace_file, rule, result_dict, rule_set)
        create_report(result_dict, name=directory)
        save_detailed_report(result_dict, rule_set, directory)
        print("\n")
        # print_result_dict(result_dict)


# Example usage
pickles_folder = 'pickles_folder'
analyze_malware_samples(pickles_folder)
