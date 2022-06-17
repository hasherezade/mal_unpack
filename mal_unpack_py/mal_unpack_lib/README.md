# Mal Unpack Python Library

This tool is a python library wrapper for Mal-unpack. Code has been adapted from the python runner.

# Getting started

1. Clone this repository:

```console
git clone https://github.com/hasherezade/mal_unpack.git
```
2. Fetch needed executables: go to [`bin`](../bin), and follow the steps from the [README](../bin/README.md).
3. Install `malunpack` library by following the [README](../mal_unpack_lib/malunpack/README.md)
4. Import `malunpack` library into your script, as in the below example:
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

# License

See [here.](https://github.com/hasherezade/mal_unpack/blob/master/LICENSE)
