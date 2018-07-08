# mal_unpack
Dynamic unpacker based on [PE-sieve](https://github.com/hasherezade/pe-sieve.git).<br/>
It deploys a packed malware, waits for it to unpack the payload, dumps the payload and kills the original process.</b><br/>
Usage:
```
mal_unpack.exe <path_to_the_malware>
```
<b>WARNING:</b> This unpacker deploys the original malware. Use it only on a VirtualMachine.
