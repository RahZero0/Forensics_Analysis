import multiprocessing
import time
import sys, os
from subprocess import run as run_it
import json

# Avoid naming conflicts by renaming the queue module and variable
from queue import Queue

start = time.time()

plugins = ["pslist" ,"dlllist", "handles", "malfind", "modules", "svcscan", "callbacks", "ldrmodules"]

class ProcessVol(multiprocessing.Process):
    """Multiprocess Volatility"""
    def __init__(self, queue):
        multiprocessing.Process.__init__(self)
        self.queue = queue

    def run(self):
        while True:
            plugin = self.queue.get()

            if plugin is None:
                break

            print(plugin)
            
            # Create plugin dir
            plugin_dir ="output/"
            if not os.path.exists(plugin_dir):
                os.makedirs(plugin_dir)

            with open(plugin_dir+"/"+plugin+".json",'w') as fp:
                run_it(['python','vol.py', '-f','memdump.raw','-r','json',f'windows.{plugin}'], stdout=fp, text=True, check=True)

            # signals to the queue job is done
            self.queue.task_done()

def main_run():
    global plugins

    console, processes = "", 8

    # populate queue with data
    if console == "":  # If not console, default plugins
        for plugin in plugins:
            queue.put(plugin)

    # run X processes
    processes_list = []
    for i in range(processes):
        p = ProcessVol(queue)
        processes_list.append(p)
        p.start()

    # wait for all processes to finish
    for p in processes_list:
        p.join()

    # add None to the queue for each process to signal termination
    for _ in processes_list:
        queue.put(None)

    # wait on the queue until everything has been processed
    queue.join()
    print("Elapsed Time: %s" % (time.time() - start))

if __name__ == "__main__":
    queue = multiprocessing.JoinableQueue()
    main_run()
