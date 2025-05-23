#!/bin/bash -eu

export PKG_CONFIG="pkg-config --static"
export PKG_CONFIG_PATH="$WORK/lib/pkgconfig"
export CPPFLAGS="-I$WORK/include"
export LDFLAGS="-L$WORK/lib"

# Run as many parallel jobs as there are available CPU cores
export MAKEFLAGS="-j$(nproc)"

# botan
pushd ../botan
./configure.py --prefix="${WORK}" --without-documentation --enable-sanitizers="${SANITIZER}" --build-targets=static,shared
make -j$(nproc) all
make install
cp build/botan-3.pc "${PKG_CONFIG_PATH}"
popd

# spank-olm
meson setup build --prefix="${WORK}" --libdir=lib --prefer-static --default-library=static --buildtype=debugoptimized \
  -Dfuzzing_engine=oss-fuzz -Dfuzzer_ldflags="$LIB_FUZZING_ENGINE" -Db_lto=false -Db_thinlto_cache=false -Dbuild_tests=false
meson install -C build --tag devel

# Copy fuzz executables to $OUT
find build/fuzz -maxdepth 1 -executable -type f -exec cp -v '{}' "${OUT}" \;

# All shared libraries needed during fuzz target execution should be inside the $OUT/lib directory
mkdir -p "${OUT}"
cp ${WORK}/lib/*.so "${OUT}/lib"

mv "${SRC}/spank-olm/fuzz/corpuses/sign.zip" "${OUT}/olm_sign_fuzzer_seed_corpus.zip"