import sys
import ctypes
import os
import time
import subprocess
from threader import main_run
from vol_mem import extract_all_features_from_memdump
from model import run_model
import shutil

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def temp_files(directory):
    # List all files in the directory
    files = os.listdir(directory)

    # Check if any file has a name starting with "tmp" or has a ".tmp" extension
    for file in files:
        if file.endswith(".tmp"):
            return True
    return False

def has_raw_files():
    # List all files in the directory
    a = "volatility3\plugins\memdump.mem"
    files = os.listdir(os.getcwd())

    # Check if any file has a name starting with "tmp" or has a ".raw" extension
    for file in files:
        if file.endswith(".raw"):
            os.rename(file, "memdump.raw")
            return a

def run_cmd(cmd):
    try:
        subprocess.run(cmd, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        pass

def final_run():
    if is_admin():
        print("Entered here")
        time.sleep(10)
        # start timing
        start_time = time.time()

        # runs magnetic and makes memdump
        run_cmd('MRCv120.exe /accepteula /go /silent')
        time.sleep(1)

        while temp_files(os.getcwd())=="1":
            time.sleep(5)

        # # changes name of raw file
        a = has_raw_files()
        time.sleep(1)

        # runs volatiltiy on it
        print("=> Running Volatility 3....")
        main_run(a)
        time.sleep(1)

        # deletes memdump.raw
        try:
            os.remove(".\memdump.raw")
        except OSError as e:
            pass
        time.sleep(1)

        # uses volmemlyzer to build trial.csv
        extract_all_features_from_memdump()
        time.sleep(1)

        # deletes volatility output
        folder_path = os.getcwd() +"\output"
        try:
            shutil.rmtree(folder_path)
        except OSError as e:
            print("Delete the output_folder manually if needed")
            pass
        time.sleep(1)
        print("=> Enteriing values into model...")
        # checks with model
        run_model()

        # end timing
        end_time = time.time()
        execution_time = end_time - start_time
        print(f"Execution time: {execution_time} seconds")
        time.sleep(10)
        sys.exit()

    else:
        # Re-run the program with admin rights
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 1)
        sys.exit()
