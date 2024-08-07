# spank_olm

[![GitHub](https://img.shields.io/github/license/MTRNord/spank_olm)](https://github.com/MTRNord/spank_olm/blob/main/LICENSE)

## Overview

`spank_olm` is a C++ library based on the [libolm](https://gitlab.matrix.org/matrix-org/olm) library
from [matrix.org](https://matrix.org). It aims to provide cryptographic functionalities similar to libolm but is not
intended for production use. The library has not undergone any security audits.

## Features

- Cryptographic operations based on libolm
- Fuzzing support for enhanced security testing
- Uses Botan3 as the cryptographic backend

## Installation

To install `spank_olm`, clone the repository and build it using Meson.

```sh
git clone https://github.com/MTRNord/spank_olm.git
cd spank_olm
meson setup build
meson compile -C build
```

To build shared libraries:

```sh
meson setup build_shared --default-library=shared
meson compile -C build_shared
```

To build static libraries:

```sh
meson setup build_static --default-library=static
meson compile -C build_static
```

To build wasm libraries:

```sh
meson setup build-wasm --cross-file wasm-cross-file.txt --default-library=static -Dbotan_wasm_path=../botan/ -Dbotan_include_path=../botan/build/include/public/ -Dcpp_std=c++2a
meson compile -C build-wasm
```

## Usage

Include `spank_olm` in your C++ project and link against it. Refer to the source code for examples of how to use the
library's functionalities.

## Fuzzing

Fuzzing is a key goal for this project. The repository includes a GitHub Actions workflow for running fuzz tests using
ClusterFuzzLite.

## License

This project is licensed under the GNU Affero General Public License, Version 3. See
the [LICENSE](https://github.com/MTRNord/spank_olm/blob/main/LICENSE) file for details.

## Disclaimer

- This library is not production-ready.
- No security audit has been performed.
- Tests are available but not yet set up on CI.

## Contributing

Contributions are welcome! Please open issues and pull requests as needed.