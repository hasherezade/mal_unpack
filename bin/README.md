##  Utils required by the Python wrappers (mal_unpack_lib, runner)

To run correctly the library requires 3 executable files:
- `mal_unpack.exe`: the lastest version available [here](https://github.com/hasherezade/mal_unpack/releases)
- `dll_load32.exe`: the dll loader for 32 bit files*
- `dll_load64.exe`: the dll loader for 64 bit files*

_*from: https://github.com/hasherezade/pe_utils_

This script will automatically download them and copy to the appropriate locations.

###  Usage:

1. Install requirements:
```console
pip install -r requirements.txt
```

2. Run using Python 3:
```console
python fetch.py
```

It should fetch all the neccessary executables
