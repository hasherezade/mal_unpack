# Mal Unpack Python Library

This tool is a python library wrapper for Mal-unpack. Code has been adapted from the python runner.

# Requirements

To run correctly the library requires 3 executable files from the main repo. 
- dll_load32.exe: the dll loader for 32 bit files
- dll_load64.exe: the dll loader for 64 bit files
- mal_unpack.exe: the lastest version available [here](https://github.com/hasherezade/mal_unpack/releases)

Once those three files are available in the 'util_exe' directory the lib can be imported and used.

# Getting started

`git clone https://github.com/hasherezade/mal_unpack.git`

```python
import malunpack

timeout = 3000 # default 2000
dump_dir = "temp/dumps"

#sample_unpack = malunpack.MalUnpack("../../sample.exe", timeout, dump_dir)

sample_unpack = malunpack.MalUnpack("sample.exe")

# Run Mal Unpack and get the JSON result from the dump folder specified
scan, dump = sample_unpack.unpack_file()

print(scan)
print(dump)
```

# Authors

- Mal_Unpack author: [@hasherezade](https://twitter.com/hasherezade)
- Mal_Unpack Lib wrapper: [@fr0gger_](https://twitter.com/fr0gger_)

# Licence

See [here.](https://github.com/hasherezade/mal_unpack/blob/master/LICENSE)