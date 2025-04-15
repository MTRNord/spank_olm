FROM gcr.io/oss-fuzz-base/base-builder:v1
RUN apt-get update && apt-get install -y \
  automake \
  autopoint \
  cmake \
  git \
  python3-pip \
  pkg-config \
  # Install the sanitizers
  libasan4 \
  liblsan0 \
  libtsan0 \
  libubsan1 \
  openssh-client


RUN pip3 install meson ninja

RUN git clone --depth 1 https://github.com/randombit/botan.git
COPY . $SRC/spank-olm

WORKDIR $SRC/spank-olm
COPY ./.clusterfuzzlite/build.sh $SRC/