#!/usr/bin/env python3

import argparse
import csv
import functools
import json
import subprocess
import tempfile
import os

def to_csv(outfile, header, dict_):
    writer = csv.DictWriter(outfile, fieldnames=header)
    writer.writeheader()
    writer.writerow(dict_)

def rc2kv(rc):
    kv = []
    keys = rc[0]
    for r in rc[0]:
        entry = {}
        kv.append(entry)
        for k, v in zip(keys, r):
            entry[k] = v
    return rc

def extract_pslist_features(procs):
    ppids = set(p['PPID'] for p in procs)
    return {
        # # of processes
        'pslist.nproc': len(procs),
        # # of parent processes
        'pslist.nppid': len(ppids),
        # Avg. thread count
        'pslist.avg_threads': sum(p['Threads'] for p in procs) / len(procs),
        # # of 64-bit processes
        'pslist.nprocs64bit': sum(p['Wow64'] for p in procs),
	    # Avg. handler count
	    'pslist.avg_handlers': sum(p['Handles'] for p in procs) / len(procs),
    }

def extract_dlllist_features(dlllist):
    # count # of pids in the report
    procs = len(set(l['PID'] for l in dlllist))
    return {
        # Total # of loaded libraries of all processes
        'dlllist.ndlls': len(dlllist),
        # Avg. loaded libraries per process
        'dlllist.avg_dlls_per_proc': len(dlllist) / procs,
    }

def extract_handles_features(handles):
    return {
        # Total # of opened handles
        'handles.nhandles': len(handles),
        # Avg. handle count per process
        'handles.avg_handles_per_proc': len(handles) / len(set(h['PID'] for h in handles)),
        # # of handles of type port
        'handles.nport': sum(1 if t['Type'] == 'ALPC Port' else 0 for t in handles),
        # # of handles of type file
        'handles.nfile': sum(1 if t['Type'] == 'File' else 0 for t in handles),
        # # of handles of type event
        'handles.nevent': sum(1 if t['Type'] == 'Event' else 0 for t in handles),
        # # of handles of type desktop
        'handles.ndesktop': sum(1 if t['Type'] == 'Desktop' else 0 for t in handles),
        # # of handles of type key
        'handles.nkey': sum(1 if t['Type'] == 'Key' else 0 for t in handles),
        # # of handles of type thread
        'handles.nthread': sum(1 if t['Type'] == 'Thread' else 0 for t in handles),
        # # of handles of type directory
        'handles.ndirectory': sum(1 if t['Type'] == 'Directory' else 0 for t in handles),
        # # of handles of type semaphore
        'handles.nsemaphore': sum(1 if t['Type'] == 'Semaphore' else 0 for t in handles),
        # # of handles of type timer
        'handles.ntimer': sum(1 if t['Type'] == 'Timer' else 0 for t in handles),
        # # of handles of type section
        'handles.nsection': sum(1 if t['Type'] == 'Section' else 0 for t in handles),
        # # of handles of type mutant
        'handles.nmutant': sum(1 if t['Type'] == 'Mutant' else 0 for t in handles),
    }

    #"{'Key', 'Session', 'Token', 'Semaphore', 'IoCompletion', 'Desktop', 'Thread', 'KeyedEvent', 'ALPC Port', 'TmRm', 'WindowStation', 'Directory', 
    # 'Section', 'File', 'Event', 'TmTm', 'TpWorkerFactory', 'EtwRegistration', 'SymbolicLink', 'WmiGuid', 'Mutant', 'Job', 'Process', 'Timer'}",

def extract_ldrmodules_features(ldrmodules):
    return {
        # # of modules missing from load list
        'ldrmodules.not_in_load': sum(1 if m['InLoad'] == 'False' else 0 for m in ldrmodules),
        # # of modules missing from init list
        'ldrmodules.not_in_init': sum(1 if m['InInit'] == 'False' else 0 for m in ldrmodules),
        # # of modules missing from mem list
        'ldrmodules.not_in_mem': sum(1 if m['InMem'] == 'False' else 0 for m in ldrmodules),
	    # avg number of modules missing from load list
        'ldrmodules.not_in_load_avg': sum(1 if m['InLoad'] == 'False' else 0 for m in ldrmodules)/ len(ldrmodules) or 1,
	    # avg number of modules missing from init list
        'ldrmodules.not_in_init_avg': sum(1 if m['InInit'] == 'False' else 0 for m in ldrmodules)/ len(ldrmodules) or 1,
	    # avg number of modules missing from mem list
        'ldrmodules.not_in_mem_avg': sum(1 if m['InMem'] == 'False' else 0 for m in ldrmodules)/ len(ldrmodules) or 1,
    }


def extract_modules_features(modules):
    return {
        'modules.nmodules': len(modules)
    }

def extract_svcscan_features(svcscan):
    return {
        'svcscan.nservices': len(svcscan),
        'svcscan.kernel_drivers': sum(1 if s['Type'] == 'SERVICE_KERNEL_DRIVER' else 0 for s in svcscan),
        'svcscan.fs_drivers': sum(1 if s['Type'] == 'SERVICE_FILE_SYSTEM_DRIVER' else 0 for s in svcscan),
        'svcscan.process_services': sum(1 if s['Type'] == 'SERVICE_WIN32_OWN_PROCESS' else 0 for s in svcscan),
        'svcscan.shared_process_services': sum(1 if s['Type'] == 'SERVICE_WIN32_SHARE_PROCESS' else 0 for s in svcscan),
        'svcscan.interactive_process_services': sum(1 if s['Type'] == 'SERVICE_INTERACTIVE_PROCESS' else 0 for s in svcscan),
        'svcscan.nactive': sum(1 if s['State'] == 'SERVICE_RUNNING' else 0 for s in svcscan),
    }

def extract_callbacks_features(callbacks):
    return {
        'callbacks.ncallbacks': len(callbacks),
        'callbacks.nanonymous': sum(1 if c['Module'] == 'UNKNOWN' else 0 for c in callbacks),
        'callbacks.ngeneric': sum(1 if c['Type'] == 'GenericKernelCallback' else 0 for c in callbacks),
    }

def extract_malfind_features(malfind):
    return {
        'malfind.ninjections': len(malfind),
        'malfind.commitCharge': sum(1 if h['Protection'] else 0 for h in malfind),
        'malfind.protection': sum(1 if h['CommitCharge'] else 0 for h in malfind),
        'malfind.uniqueInjections': len(malfind) / len(set(h['PID'] for h in malfind)),
    }

VOL_MODULES = {
    'pslist': extract_pslist_features,
    'dlllist': extract_dlllist_features,
    'handles': extract_handles_features,
    'ldrmodules': extract_ldrmodules_features,
    'malfind': extract_malfind_features,
    'modules': extract_modules_features,
    'svcscan': extract_svcscan_features,
    'callbacks': extract_callbacks_features,
}

def extract_all_features_from_memdump():
    features = {}
    output_to = "trial.csv"
    print(f"=> Outputting to {output_to}...")

    for module, extractor in VOL_MODULES.items():

        output_file_path = "output/"+module+'.json'
        try:
            with open(output_file_path, 'r') as file:
                procs = rc2kv(json.load(file))
                features.update(extractor(procs))
    
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON: {e}")

    with open(output_to, 'w',newline='') as f:
        to_csv(f, features.keys(), features)
