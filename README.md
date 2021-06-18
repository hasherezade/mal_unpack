# mal_unpack
[![Build status](https://ci.appveyor.com/api/projects/status/3cqqlah6unfhasik?svg=true)](https://ci.appveyor.com/project/hasherezade/mal-unpack)

Dynamic unpacker based on [PE-sieve](https://github.com/hasherezade/pe-sieve.git).<br/>
It deploys a packed malware, waits for it to unpack the payload, dumps the payload, and kills the original process.</b><br/>

Usage
-

```console
mal_unpack.exe /exe <path_to_the_malware> /timeout <timeout: ms>
```

**WARNING:** This unpacker deploys the original malware. Use it only on a VirtualMachine.

Clone
-
Use **recursive clone** to get the repo together with submodules:

```console
git clone --recursive https://github.com/hasherezade/mal_unpack.git
```
