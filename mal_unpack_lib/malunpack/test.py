import malunpack

#sample_unpack = malunpack.MalUnpack("../../sample.exe", timeout, dump_dir)

sample_unpack = malunpack.MalUnpack("../../mal_unpack_py/calc.exe")

# Get some basic details about the sample
#print(sample_unpack.filename)
#print(sample_unpack.calc_sha())
#print(sample_unpack.is_dll)

# Get the JSON result from MalUnpack
scan, dump = sample_unpack.unpack_file()
print(scan)
print(dump)