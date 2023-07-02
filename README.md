# Dynamic CAPA
Project implemented by Fredrik SVEEN, Lenia MALKI and Olivier BREDIN.

## Project Description
The aim of the project is to develop a framework capable of dynamically scanning API calls made by malware samples during their execution and identifying patterns and behaviors that correspond to malware capabilities. By identifying specific patterns and behaviors, it becomes possible to detect and understand the capabilities and intentions of the malware. When analyzing the malwares, the behaviour is compared to the rules specified by the *MITRE ATT&CK®* which is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. All the different techniques specified in *MITRE ATT&CK®* can be found [here](https://attack.mitre.org/techniques/enterprise/). All the different techniques are categorized in 14 different tactics (i.e. groups of techniques):
- Reconnaissance
- Resource Development
- Initial Access
- Execution
- Persistence
- Privilege Escalation
- Defense Evasion
- Credential Access
- Discovery
- Lateral Movement
- Collection
- Command and Control
- Exfiltration
- Impact

During the dynamic analysis, each malware sample will be matched against all implemented rules in the `\json` folder. In this folder, each specific rule have a `json`-file named after the ID of the specific rule.

## Usage

### Scripts:

- `classes.py`: contains the class used for loading the pickle file(s)
- `read_pickle.py`: command line script for computing stats about several pickle files

### `classes.py`:

It only contains the class **DynAnal** which tracks the dynamic behavior of a sample:
- sha256: sha256 checksum of the file
- orderedEvents: list of API calls executed by the sample itself and the eventual children/injected processes
- evasiveBehaviour: dict of evasive API calls, where each element has as key the category of evasion and as value the list of API names/description associated to that category (must be retrieved with the method get_evasive_behaviour)
- pidToEvents: dict subset of orderedEvents with the API calls executed by the original sample and its children, grouped by pid
- pidToHoneypotEvents: dict subset of orderedEvents with the API calls executed by  eventual injected processes/dlls, grouped by pid

It also has several methods where the most important ones are functions that matches the malware with the different rules specified in the `json`-files:
- `json_registry_match(self, j)`
    - *Add short explanation for each*
- `json_process_match(self, j)`
- `json_file_match(self, j)`

### `read_pickles.py`:
This script requires the file path of the the forlder of the pickles files as an argument, and can be called in the terminal like this:
```bash
./read_pickles.py PICKLES_FOLDER
```

This script analyzes all the pickle files contained in the specified folder provinding different stats about all the samples:

- tot_samples: total number of samples analyzed
- broken_pickle: number of pickle files that could not be loaded
- empty_samples: number of empty pickles
- evasive_samples: percentage of samples using at least one evasive technique
- injection_samples: percentage of samples performing injection
- n_of_events: min, max, median, mean, stdev of the number of events executed by all the samples
- n_of_processes: min, max, median, mean, stdev of number of processes executed by all the samples
- Evasive: percentage of the different evasion techniques used by all the samples, grouped by category 

## Types of information
All the calls within each pickle file is classified by one of the the following types, and one category:
- BEH = Behaviour with Sym (symbol)
    - Cat: 'PROCESS', 'NETWORK', 'MUTEX', 'THREAD'
- BEHwA = Behaviour with Sym (symbol) and Argument
    - Cat: 'REGISTRY', 'FILESYSTEM', 'PROCESS', 'MUTEX', 'SERVICE', 'NETWORK'
- EVA = Evasive 
    - Cat: 'ANTIDUMP', 'ENVIRONMENT PROFILING', 'ANTIDEBUG', 'GENERIC SANDBOX CHECK', 'TIMING ATTACK'
- ERR = Error 
    - No categories
- INF = Information 
    - *I believe that there is some categories here as well*


## INF type tree
Type: INF (information)
Key list: ['Time', 'Type', 'Title', 'Desc']
- (Title)
        - (Desc example)
- JLP MD5
        - ed0b3cfd7ca4890730d9d8f9bce1e706
- PROCESS NAME
        - C:\Users\GuannaPenna\9V3CFUKU.exe
- BASEADDRESS
        - 0x2b0000
- MSVC
        - Found cpuid(0x1) that match MSVC compiler routine
- WRITEONPEHEADEROFFSET
        - 272
- VIRTUAL ALLOC EXEC
        - 0xc630000
- WRITE PROCESS MEMORY
        - C:\Windows\Microsoft.NET\Framework\v2.0.50727\RegAsm.exe
- CHILDPROCESS CMD
        - C:\Windows\Microsoft.NET\Framework\v2.0.50727\RegAsm.exe
- CHILDPROCESS PID
        - 2688
- TIMEOUT
        - The program exited for timeout -> Elapsed 300 seconds
- EXITCODE
        - 2
- PROGRAM INSTRUCTIONS
        - 0
- LIBRARY INSTRUCTIONS
        - 0
- VIRTUAL PROTECT
        -  0x7701f125
- SUSPECT DLL
        - C:\Users\GuannaPenna\sxeA1CC.tmp
- INJECTION
        - 8
- PROCESS ENUMERATION
        - Potential detection of pin.exe through Process32Next

## BEH type tree

Type: BEH (Behaviour)
Key list: ['Time', 'Type', 'Cat', 'Sym']
- (Cat)
    - (Sym)
- PROCESS
    - NtProtectVirtualMemory
    - NtOpenSection
    - NtCreateSection
    - ZwMapViewOfSection
    - NtAllocateVirtualMemory
    - ZwFreeVirtualMemory
    - NtUnmapViewOfSection
    - NtOpenProcess
    - ZwTerminateProcess
    - ZwAllocateVirtualMemory
    - NtCreateUserProcess
    - ZwWriteVirtualMemory
    - NtReadVirtualMemory
    - ChildProcess
    - ZwOpenProcess
    - NtTerminateProcess
- MUTEX
    - NtCreateMutant
- THREAD
    - NtCreateThreadEx
    - ZwResumeThread
    - ZwCreateThreadEx
    - NtGetContextThread
    - ZwSetContextThread
    - ZwTerminateThread
    - ZwOpenThread
    - NtOpenThread
    - NtQueueApcThread
    - NtResumeThread
    - NtSuspendThread
- NETWORK
    - HttpSendRequestW
    - HttpSendRequestA
    - InternetWriteFile

## BEHwA type tree

Type: BEHwA (Behaviour)
Key list: ['Time', 'Type', 'Cat', 'Sym', 'Arg']
- Cat
    - Sym (Arg)
- REGISTRY
    - NtOpenKeyHook (None)
    - NtQueryValueKey (\REGISTRY\MACHINE\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers)
    - NtCreateKey (\REGISTRY\USER\S-1-5-21-1715841133-416286900-2289519084-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU)      
    - NtSetValueKey (\REGISTRY\USER\S-1-5-21-1715841133-416286900-2289519084-1000\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer)  
    - NtDeleteKey (\REGISTRY\USER\S-1-5-21-1715841133-416286900-2289519084-1000\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap)
- FILESYSTEM
    - NtQueryAttributesFile (\??\C:\Users\GuannaPenna\WSOCK32.dll)
    - NtOpenFile (\Device\HarddiskVolume2\Windows\System32\wsock32.dll)
    - NtQueryInformationFile (\Device\HarddiskVolume2\Windows\WindowsShell.Manifest)
    - NtReadFile (\Device\NamedPipe\W32PosixPipe.00000f1c.00000007)
    - NtDeviceIoControlFile (\Device\KsecDD)
    - CreateFileW (C:\Users\GuannaPenna\9V3CFUKU.exe)
    - NtCreateFile (\Device\HarddiskVolume2\Users\GuannAPenna\9V3CFUKU.exe)
    - NtSetInformationFile (\Device\HarddiskVolume2\Windows\Microsoft.NET\Framework\v2.0.50727\RegAsm.exe)
    - CreateFileA (\\.\SICE)
    - NtWriteFile (\Device\HarddiskVolume2\Users\GuannAPenna\AppData\Local\Temp\logrdeventsmaxo4.cfg)
    - DeleteFileA (C:\Users\GuannaPenna\sxeA1CD.tmp)
    - DeleteFileW (C:\Users\GuannaPenna\sxeA1CD.tmp)
- MUTEX
    - NtCreateMutant (runas)
    - NtOpenMutant (Local\!IETld!Mutex)
- PROCESS
    - NtOpenProcess (C:\pin\source\tools\JuanLesPIN\Release\Honeypot.exe)
    - ZwOpenProcess (C:\Users\Slasti\X8JWK4G1.exe)
    - NtCreateUserProcess (C:\Windows\System32\WerFault.exe)
- NETWORK
    - inet_addr (localhost)
    - URLDownloadToFileW (http://aurora.bitnamiapp.com/tratador/sub003473.rar)
        - InternetOpenW (Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0))
    - InternetOpenA (Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0))
    - connect (127.0.0.1:55723)
    - InternetConnectW (aurora.bitnamiapp.com)
    - InternetConnectA (aurora.bitnamiapp.com)
    - InternetOpenUrlA (https://cdn.discordapp.com/attachments/851129144217829379/851813349745623050/Qtepsknsyefcoyubojldkppprkszlta)
    - URLDownloadToFileA (http://20.87.46.185/unmy.bmp)
- SERVICE
    - OpenSCManagerA (HANDLE=0x00000000)
    - OpenServiceA (rasman)
    - OpenSCManagerW (HANDLE=0x00000000)
    - OpenServiceW (NAME=AudioSrvHANDLE=0x002a0ef8)
    - ControlService (HANDLE=0x001aedd8)
    - CreateServiceA (dahiService)
    - StartServiceA (HANDLE=0x006810d0)
    - DeleteService (HANDLE=0x02aa3601)

## Remaining tasks

[ ] README file         Olivier

[ ] Log file for detailed info about matches (<malware>_<timestamp>.log)        Léa
  - Add the log file
  - check which info to put in the logs

[ ] Add verbose or do another bigger report with more info (ex. Name of the rule)       Olivier
  - Optional: format it as a matrix

[ ] Check if there are other rules that can be implemented in the FILESYSTEM category