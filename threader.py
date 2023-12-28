#!/usr/bin/python
import queue
import threading
import time
import sys, os, getopt
from subprocess import run as run_it
import json

queue = queue.Queue()
start = time.time()

plugins = ["pslist" ,"dlllist", "handles", "malfind", "modules", "svcscan", "callbacks", "ldrmodules"]

class ThreadVol(threading.Thread):
    """Threaded Volatility"""
    def __init__(self, queue, memdump):
        threading.Thread.__init__(self)
        self.queue = queue
        self.memdump = memdump

    def run(self):
        plugin = self.queue.get()

        # print(plugin)                # this also can be given ot the fornt end
        
        # Create plugin dir
        plugin_dir ="output/"
        if not os.path.exists(plugin_dir):
            os.makedirs(plugin_dir)


        with open(plugin_dir+"/"+plugin+".json",'w') as fp:
            run_it(['python','vol.py', '-f',self.memdump,'-r','json',f'windows.{plugin}'], stdout=fp, text=True,check=True)

        #signals to queue job is done
        self.queue.task_done()

def main_run(memdump):
    global plugins

    console, threads = "", 8

    #populate queue with data
    if console == "": # If not console, default plugins
        for plugin in plugins:
            queue.put(plugin)

    #run X threads
    for i in range(threads):
        t = ThreadVol(queue, memdump)
        t.setDaemon(True)
        t.start()
        time.sleep(0.1)

    #wait on the queue until everything has been processed     
    queue.join()

    elasped_time = time.time() - start      # give this to front end or keep it into database
