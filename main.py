import os
import pickle
from classes import DynAnal

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
    print("##### api_calls: #####")
    for e in api_calls:
        print(e)
        #if event['Type'] == 'INF':
            #print("Injection event is detected:",event)
    print("########################")

def print_evasive_behavior(evasive_behavior):
    print("##### evasive_behavior: #####")
    for category, api_names in evasive_behavior.items():
        print(f"Category: {category}")
        for api_name in api_names:
            print(f"- API Name: {api_name}")
    print("########################")

def print_process_info(process_info):
    print("##### process_info: #####")
    print("Process IDs from pidToEvents:", list(process_info['pidToEvents'].keys()))
    print("Process IDs from honeypotEvents:", list(process_info['pidToHoneypotEvents'].keys()))
    print("########################")

# Example usage
pickles_folder = 'pickles_folder/bestafera/'

def analyze_malware_samples(pickles_folder):
    for filename in os.listdir(pickles_folder):
        file_path = os.path.join(pickles_folder, filename)
        dynanal = load_pickle_file(file_path)
        api_calls, evasive_behavior, process_info = extract_information(dynanal)
        print_api_calls(api_calls)
        print_evasive_behavior(evasive_behavior)
        print_process_info(process_info)
        break # Set to only process 1 subfolder atm

analyze_malware_samples(pickles_folder)
