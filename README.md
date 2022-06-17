# mal_unpack

[![Build status](https://ci.appveyor.com/api/projects/status/3cqqlah6unfhasik?svg=true)](https://ci.appveyor.com/project/hasherezade/mal-unpack)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/fedbe124aa694761907bbe51bfc8d6f9)](https://app.codacy.com/gh/hasherezade/mal_unpack/dashboard?branch=master)
[![Commit activity](https://img.shields.io/github/commit-activity/m/hasherezade/mal_unpack)](https://github.com/hasherezade/mal_unpack/commits)
[![Last Commit](https://img.shields.io/github/last-commit/hasherezade/mal_unpack/master)](https://github.com/hasherezade/mal_unpack/commits)

[![GitHub release](https://img.shields.io/github/release/hasherezade/mal_unpack.svg)](https://github.com/hasherezade/mal_unpack/releases)
[![GitHub release date](https://img.shields.io/github/release-date/hasherezade/mal_unpack?color=blue)](https://github.com/hasherezade/mal_unpack/releases)
[![Github All Releases](https://img.shields.io/github/downloads/hasherezade/mal_unpack/total.svg)](https://github.com/hasherezade/mal_unpack/releases)
[![Github Latest Release](https://img.shields.io/github/downloads/hasherezade/mal_unpack/latest/total.svg)](https://github.com/hasherezade/mal_unpack/releases)

[![License](https://img.shields.io/badge/License-BSD%202--Clause-blue.svg)](https://github.com/hasherezade/mal_unpack/blob/master/LICENSE)
[![Platform Badge](https://img.shields.io/badge/Windows-0078D6?logo=windows)](https://github.com/hasherezade/mal_unpack)

Dynamic unpacker based on [PE-sieve](https://github.com/hasherezade/pe-sieve.git).<br/>
It deploys a packed malware, waits for it to unpack the payload, dumps the payload, and kills the original process.</b>

📖 Read more on [PE-sieve's Wiki](https://github.com/hasherezade/pe-sieve/wiki/1.-FAQ#pe-sieve-vs-malunpack---what-is-the-difference).
<br/>

## Usage

```console
mal_unpack.exe /exe <path_to_the_malware> /timeout <timeout: ms>
```

**WARNING:** This unpacker deploys the original malware. Use it only on a VirtualMachine.

ℹ For the best performance, install [MalUnpackCompanion driver](https://github.com/hasherezade/mal_unpack_drv).

ℹ Check also the python wrapper: [MalUnpack Runner](https://github.com/hasherezade/mal_unpack/tree/master/runner)

ℹ Check the python Library: [MalUnpack Lib](https://github.com/fr0gger/mal_unpack/tree/master/mal_unpack_lib)

## Clone

Use **recursive clone** to get the repo together with submodules:

```console
git clone --recursive https://github.com/hasherezade/mal_unpack.git
```

## Builds

Download the latest [release](https://github.com/hasherezade/mal_unpack/releases).
