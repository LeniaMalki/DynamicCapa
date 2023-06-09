# Usage

## Scripts

- classes.py: contains the class used for loading the pickle file(s)
- read_pickle.py: command line script for computing stats about several pickle files

### classes.py

It only contains the class **DynAnal** which tracks the dynamic behavior of a sample:
- sha256: sha256 checksum of the file
- orderedEvents: list of API calls executed by the sample itself and the eventual children/injected processes
- evasiveBehaviour: dict of evasive API calls, where each element has as key the category of evasion and as value the list of API names/description associated to that category (must be retrieved with the method get_evasive_behaviour)
- pidToEvents: dict subset of orderedEvents with the API calls executed by the original sample and its children, grouped by pid
- pidToHoneypotEvents: dict subset of orderedEvents with the API calls executed by  eventual injected processes/dlls, grouped by pid

### read_pickles.py

```bash
./read_pickles.py PICKLES_FOLDER
```

Analyzes all the pickle files contained in the specified folder provinding different stats about all the samples:

- tot_samples: total number of samples analyzed
- broken_pickle: number of pickle files that could not be loaded
- empty_samples: number of empty pickles
- evasive_samples: percentage of samples using at least one evasive technique
- injection_samples: percentage of samples performing injection
- n_of_events: min, max, median, mean, stdev of the number of events executed by all the samples
- n_of_processes: min, max, median, mean, stdev of number of processes executed by all the samples
- Evasive: percentage of the different evasion techniques used by all the samples, grouped by category 