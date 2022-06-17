#!/usr/bin/env python3
   
import requests
import zipfile
import os
from pathlib import Path

url1 = 'https://github.com/hasherezade/pe_utils/releases/download/1.0/dll_load32.exe'
url2 = 'https://github.com/hasherezade/pe_utils/releases/download/1.0/dll_load64.exe'
url_mal_unp32 = "https://github.com/hasherezade/mal_unpack/releases/download/0.9.5/mal_unpack32.zip"
url_mal_unp64 = "https://github.com/hasherezade/mal_unpack/releases/download/0.9.5/mal_unpack64.zip"

def download_file(filename, url):  
    try:
        r = requests.get(url, allow_redirects=True)
    except:  
        return False
        
    if r.status_code != 200 or r.content is None:
        return False
        
    open(filename, 'wb').write(r.content)
    return True
    
def is_windows_64bit():
    return os.environ['PROCESSOR_ARCHITECTURE'].endswith('64')

def main():
    url_mal_unp = url_mal_unp32
    if (is_windows_64bit()):
        url_mal_unp = url_mal_unp64
        
    urls = {"dll_load32.exe" : url1, "dll_load64.exe" : url2, "mal_unpack.zip" : url_mal_unp}
    for fname in urls:
        if not download_file(fname, urls[fname]):
            print("[-] Could not download: " + fname)
            continue

        p = Path(fname)
        ext = p.suffix
        print("[+] Downloaded: " + fname)
        if ext == ".zip":
            with zipfile.ZipFile(fname,"r") as zip_ref:
                zip_ref.extractall(".")
            print("[+] Unpacked: " + fname)
            os.remove(fname)

if __name__ == "__main__":
    main()
