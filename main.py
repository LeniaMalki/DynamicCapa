import os
import pickle
from classes import DynAnal
import json

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

# Example usage
pickles_folder = 'pickles_folder'

def analyze_malware_samples(pickles_folder):
    L = []
    for directory in os.listdir(pickles_folder):
        print("########################")
        print(directory)
        print("########################")
        for filename in os.listdir(os.path.join(pickles_folder, directory)):
            file_path = os.path.join(pickles_folder, directory, filename)
            dynanal = load_pickle_file(file_path)
            api_calls, evasive_behavior, process_info = extract_information(dynanal)
            with open('json/T1547_003.json') as f:
                dynanal.json_registry_match(json.load(f))
            '''print_api_calls(api_calls)
            print_evasive_behaviour(evasive_behavior)
            print_process_info(process_info)
            print("\n")
            '''
            #L = L + dynanal.get_all_categories()
            #break # Set to only process 1 .pickle atm
    #print("Categories:")
    #L = list(dict.fromkeys(L))
    #for t in L:
        #print(f"\t- {t}")

analyze_malware_samples(pickles_folder)
