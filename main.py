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
pickles_folder = 'pickles_folder/bestafera/'

def analyze_malware_samples(pickles_folder):
    for filename in os.listdir(pickles_folder):
        file_path = os.path.join(pickles_folder, filename)
        dynanal = load_pickle_file(file_path)
        api_calls, evasive_behavior, process_info = extract_information(dynanal)
        print_api_calls(api_calls)
        print_evasive_behaviour(evasive_behavior)
        print_process_info(process_info)
        print("\n")
        break # Set to only process 1 .pickle atm

analyze_malware_samples(pickles_folder)
