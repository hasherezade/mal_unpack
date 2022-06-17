#!/usr/bin/env python3
"""This is a library wrapper for Mal-Unpack.
   Mal-Unpack author: @hasherazade
   Mal_Unpack_Lib wrapper author: @fr0gger_ """

import sys
import os
import subprocess
from pathlib import Path
import shutil
import uuid
import hashlib
import json
import pefile

# Mal-Unpack path and DLL loaders
UTIL_PATH="../../util_exe/"
MAL_UNPACK_EXE = UTIL_PATH + "mal_unpack.exe"
DLL_LOAD64 = UTIL_PATH + "dll_load64.exe"
DLL_LOAD32 = UTIL_PATH + "dll_load32.exe"


class MalUnpack:
    """ MalUnpack Python Class wrapper for Mal-Unpack exe.
        Unpacking malware samples using mal-unpack executable.

        Classes:
            malUnpack

        Functions:
            calc_sha(FILE)
            rename_sample(FILE, IS_DLL)
            run_and_dump(FILE, DUMP_DIR, TIMEOUT)
            unpack_file(FILE) - Main Runner
    """
    def __init__(self, filename, timeout=2000, dump_dir="dumps"):
        # Load PE and check characteristics and architecture
        try:
            exe = pefile.PE(filename, fast_load=True)
            self.is_dll = False
            if exe.is_exe() is False:
                self.is_dll = True
                self.is_64b = None

            if exe.OPTIONAL_HEADER.Magic == 0x10b:
                self.is_64b = False

            elif exe.OPTIONAL_HEADER.Magic == 0x20b:
                self.is_64b = True
            exe.close()

        except OSError as error:
            print(error)
            sys.exit()

        except pefile.PEFormatError as error:
            print(error.value)
            sys.exit()

        self.filename = filename
        self.timeout = timeout
        self.task_name = str(uuid.uuid4())
        self.dump_dir = dump_dir

    def calc_sha(self):
        """calculate sha256"""
        with open(self.filename, "rb") as sample_file:
            rbytes = sample_file.read()
            sha_digest = hashlib.sha256(rbytes).hexdigest()
            return sha_digest

    def rename_sample(self, is_dll):
        """renaming the sample"""
        pathfile = Path(self.task_name)
        new_ext = ".exe"
        if is_dll:
            new_ext = ".dll"
        new_name = pathfile.stem + new_ext
        directory = str(pathfile.parent)
        pathfile.rename(Path(pathfile.parent, new_name))
        abs_name = directory + os.path.sep + new_name
        return abs_name

    def run_and_dump(self, dump_dir, timeout):
        """Main function that runs the mal-unpack executable."""
        # check required executable from malunpack:
        if not os.path.isfile(MAL_UNPACK_EXE):
            print("[ERROR] " + MAL_UNPACK_EXE + " not in current directory")
            sys.exit()
        if not os.path.isfile(DLL_LOAD64):
            print("[ERROR] " + DLL_LOAD64 + " not in current directory")
            sys.exit()
        if not os.path.isfile(DLL_LOAD32):
            print("[ERROR] " + DLL_LOAD32 + " not in current directory")
            sys.exit()

        sample = self.rename_sample(self.is_dll)
        print(sample)

        cmd = [MAL_UNPACK_EXE,
        '/timeout', str(timeout),
        '/dir', dump_dir,
        '/img', sample,
        '/hooks', '1',
        '/shellc', '1',
        '/trigger', 'T']

        if self.is_dll:
            cmd.append('/cmd')

            # run the first exported function
            cmd.append(sample + ' #1')
            if self.is_64b:
                sample = DLL_LOAD64
            else:
                sample = DLL_LOAD32

        cmd.append('/exe')
        cmd.append(sample)
        result = subprocess.run(cmd, check=False, capture_output=True)
        os.remove(sample)

        returncodedic = {-1: "ERROR", 0: "INFO", 1: "NOT_DETECTED", 2: "DETECTED"}

        if result.returncode is None:
            print("[!] mal_unpack failed to run")
            sys.exit()

        for code, value in returncodedic.items():
            if result.returncode == code:
                print("[INFO] mal_unpack result: " + value)

        print("\n[INFO] Mal Unpack exe output:")
        print((result.stdout).decode('utf-8'))

        if result.stdout is None:
            print("[!] mal_unpack failed to run")
        if not os.path.exists(self.dump_dir):
            os.makedirs(self.dump_dir)

        filepath = self.dump_dir + os.path.sep + "mal_unp.stdout.txt"
        with open(filepath, "ab") as handle:
            handle.write(result.stdout)

    def unpack_file(self):
        """Unpacking the sample and copy in the right directory."""
        sample_hash = self.calc_sha()
        dir_name = self.dump_dir + os.path.sep + sample_hash
        print("[+] Dump Directory: " + dir_name)
        shutil.copy(self.filename, self.task_name)

        self.run_and_dump(dir_name, self.timeout)

        # check result JSON
        resultpath = self.dump_dir + os.path.sep + self.calc_sha()

        dump_json = None
        scan_json = None
        # store json file to variable and return to caller
        for root, dirs, files in os.walk(resultpath):
            for name in files:
                if name.endswith("scan_report.json"):
                    jsonpath = root + os.path.sep + name
                    # print("[INFO] Scan json: " + jsonpath)
                    scanjson = open(jsonpath)
                    scan_json = json.load(scanjson)

                if name.endswith("dump_report.json"):
                    jsonpath = root + os.path.sep + name
                    # print("[INFO] Dump json: " + jsonpath)
                    dumpjson = open(jsonpath)
                    dump_json = json.load(dumpjson)

        return(scan_json, dump_json)