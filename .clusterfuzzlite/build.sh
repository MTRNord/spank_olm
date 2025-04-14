#!/bin/bash -eu

export PKG_CONFIG="pkg-config --static"
export PKG_CONFIG_PATH="$WORK/lib/pkgconfig"

# Run as many parallel jobs as there are available CPU cores
export MAKEFLAGS="-j$(nproc)"

# botan
pushd ../botan
./configure.py --prefix="${WORK}" --with-sanitizers
make
make install
cp build/botan-3.pc "${PKG_CONFIG_PATH}"
popd

export CPPFLAGS="-I$WORK/include"
export LDFLAGS="-L$WORK/lib"

# spank-olm
meson setup build --prefix="${WORK}" --libdir=lib --prefer-static --default-library=static --buildtype=debugoptimized \
  -Dfuzzing_engine=oss-fuzz -Dfuzzer_ldflags="$LIB_FUZZING_ENGINE" -Db_lto=false -Db_thinlto_cache=false -Dbuild_tests=false \
  -Dcpp_link_args="$LDFLAGS -Wl,-rpath=\$ORIGIN"
meson install -C build --tag devel

# Copy fuzz executables to $OUT
find build/fuzz -maxdepth 1 -executable -type f -exec cp -v '{}' "${OUT}" \;

# All shared libraries needed during fuzz target execution should be inside the $OUT/lib directory
mkdir -p "${OUT}"
cp ${WORK}/lib/*.so "${OUT}/lib"

# TODO: This is from libvips and needs adjusting:

## Merge the seed corpus in a single directory, exclude files larger than 4k
#mkdir -p fuzz/corpus
#find \
#  $SRC/afl-testcases/{gif*,jpeg*,png,tiff,webp}/full/images \
#  fuzz/*_fuzzer_corpus \
#  test/test-suite/images \
#  -type f -size -4k \
#  -exec bash -c 'hash=($(sha1sum {})); mv {} fuzz/corpus/$hash' \;
#zip -jrq $OUT/seed_corpus.zip fuzz/corpus
#
## Link corpus
#for fuzzer in fuzz/*_fuzzer.cc; do
#  target=$(basename "$fuzzer" .cc)
#  ln -sf "seed_corpus.zip" "$OUT/${target}_seed_corpus.zip"
#done
#
## Copy options and dictionary files to $OUT
#find fuzz -name '*_fuzzer.dict' -exec cp -v '{}' $OUT \;
#find fuzz -name '*_fuzzer.options' -exec cp -v '{}' $OUT \;