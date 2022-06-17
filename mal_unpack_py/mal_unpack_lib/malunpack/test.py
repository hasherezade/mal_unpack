import malunpack # malunpack library
import requests # for downloading the example

def download_file(filename, url):  
    try:
        r = requests.get(url, allow_redirects=True)
    except:  
        return False
        
    if r.status_code != 200 or r.content is None:
        return False
        
    open(filename, 'wb').write(r.content)
    return True

def main():
    sample_name = "RunPE.exe"
    sample_url = "https://github.com/hasherezade/pesieve_tests/blob/main/32b/runpe/RunPE.exe?raw=true"
    if not download_file(sample_name,sample_url):
        print("[-] Downloading of the example failed!")
        exit(-1)

    #sample_unpack = malunpack.MalUnpack(sample_name, timeout, dump_dir)
    sample_unpack = malunpack.MalUnpack(sample_name)

    # Get some basic details about the sample
    #print(sample_unpack.filename)
    #print(sample_unpack.calc_sha())
    #print(sample_unpack.is_dll)

    # Get the JSON result from MalUnpack
    scan, dump = sample_unpack.unpack_file()
    
    print("Scan report:")
    print(scan)
    
    print("Dump report:")
    print(dump)
    
if __name__ == "__main__":
    main()
