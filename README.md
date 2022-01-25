\mainpage README
<h1 align="center">
   <a href="http://adequate.biz">
      <img alt="Adequate Systems" src="https://raw.githubusercontent.com/adequatesystems/.github/main/media/adqlogo_banner.svg" /></a>
   <br/>Crypto C/C++ Library<br/>
   <a href="https://github.com/adequatesystems/crypto-c/actions/workflows/tests.yaml">
      <img src="https://github.com/adequatesystems/crypto-c/actions/workflows/tests.yaml/badge.svg" alt="tests status" /></a>
   <a href="https://github.com/adequatesystems/crypto-c/actions/workflows/codeql.yaml">
      <img src="https://github.com/adequatesystems/crypto-c/actions/workflows/codeql.yaml/badge.svg" alt="codeql status" /></a>
   <a href="https://codecov.io/gh/adequatesystems/crypto-c">
      <img src="https://codecov.io/gh/adequatesystems/crypto-c/graph/badge.svg" alt="coverage status"></a>
   <br/>
   <a href="LICENSE.md">
      <img src="https://img.shields.io/badge/_License-CC0_v1.0-%23.svg?logoColor=lightgreen&logo=open%20source%20initiative&labelColor=2d3339&color=0059ff" alt="Creative Commons Zero v1.0 Universal" /></a>
   <a href="https://github.com/adequatesystems/crypto-c/releases">
      <img src="https://img.shields.io/github/release/adequatesystems/crypto-c.svg?logo=semantic-release&labelColor=2d3339&label=Release&color=%230059ff" alt="release version"></a>
</h1>

Originally based on various contributions released into the Public Domain, this repository contains Cryptographic C/C++/CUDA support intended for continued use in the Open Source community.

### Usage
Generally, hashing functions may be used by declaring an algorithms "context", and calling initial, update and final hash functions as required, OR; by simply calling the convenient "all-in-one" function that handles the algorithm's steps internally.

For example, the popular SHA256 algorithm may be used with a single call:
```c
#include "sha256.h"

void simple_hash(void *data, size_t datalen, void *out)
{
   sha256(data, datalen, out);
}
```
OR; it may be used with more control:
```c
#include "sha256.h"

void thrice_hash(void *data, size_t datalen, void *out)
{
   SHA256_CTX ctx;

   sha256_init(&ctx);
   sha256_update(&ctx, data, datalen);
   sha256_update(&ctx, data, datalen);
   sha256_update(&ctx, data, datalen);
   sha256_final(&ctx, out);
}
```

Most hashing algorithms follow the same syntax. For specific usage information, see the [documentation](https://adequatesystems.github.io/crypto-c/).

## Installation
*<sup>Due to the nature of contributions from various origins, ensure you understand the information in the [License](#License) section before use.</sup>*

The Crypto C/C++ Library was designed to be included in other projects as a [Git Submodule](https://git-scm.com/book/en/v2/Git-Tools-Submodules). For C projects utilizing a similar structure and makefile, it is recommended to add submodules to the `include/` directory of "superproject".

*If the "superproject" DOES NOT utilize a similar structure and makefile, you may have to include additional commands in your build process to build submodule files.*

### Add Crypto C as Submodule to project-repo
```sh
cd project-repo
git submodule add https://github.com/adequatesystems/crypto-c include/crypto-c
git commit -m "include crypto-c submodule"
```

### Update Crypto C Submodule to latest revision
```sh
cd project-repo/include/crypto-c
git pull && git commit -m "update crypto-c submodule to latest revision"
```

### Change Crypto C Submodule to specific hash or version tag
```sh
cd project-repo/include/crypto-c
git fetch
git checkout <hash or version tag>
git commit -m "checkout crypto-c submodule to <hash or version tag>"
```

## License
The Makefile and Extended C/C++ library used for convenient building and testing of cryptographic algorithms is licensed separately to this repository. See <https://github.com/adequatesystems/extended-c/> for more information on that license.

The source for SHA3 is (re)released under the MIT license (MIT) which can be viewed in the relevant [source](src/sha3.c) and [header](src/sha3.h) files.

The source for Blake2b, CRC16, CRC32, MD2, MD5, SHA1, SHA256 and the associated device utility header is released into the Public Domain under the Creative Commons Zero v1.0 Universal [license](LICENSE.md).
