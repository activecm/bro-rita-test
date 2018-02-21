FROM alpine:3.7

LABEL maintainer "https://github.com/blacktop"

ENV BRO_VERSION 2.5.2

COPY patches /tmp
RUN apk add --no-cache zlib openssl cyrus-sasl libstdc++ libpcap geoip libgcc tini python2 git cmake
RUN apk add --no-cache -t .build-deps \
                          linux-headers \
                          openssl-dev \
                          cyrus-sasl-dev \
                          libpcap-dev \
                          python2-dev \
                          py2-pip \
                          geoip-dev \
                          zlib-dev \
                          binutils \
                          fts-dev \
                          clang \
                          bison \
                          perl \
                          make \
                          flex \
                          git \
                          g++ \
                          fts

RUN echo "===> Installing mongocxx" \
  && cd /tmp \
  && wget -q https://github.com/mongodb/mongo-c-driver/releases/download/1.9.2/mongo-c-driver-1.9.2.tar.gz \
  && tar xzf mongo-c-driver-1.9.2.tar.gz \
  && cd mongo-c-driver-1.9.2 \ 
  && CC=clang ./configure --disable-automatic-init-and-cleanup --enable-static \
  && make \
  && make install \
  && cd /tmp \
  && wget -q https://github.com/mongodb/mongo-cxx-driver/archive/r3.1.3.tar.gz \
  && tar xzf r3.1.3.tar.gz \
  && cd mongo-cxx-driver-r3.1.3/build \
  && cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local .. \
  && make \
  && make install

#Invalidate cache when master is updated
ADD https://api.github.com/repos/ocmdev/bro-mongodb/git/refs/heads/master /tmp/version.json

RUN echo "===> Applying Bro patches..." \
  && cd /tmp \
  && git clone --recursive --branch v$BRO_VERSION git://git.bro.org/bro \
  && cd /tmp/bro \
  && patch -p1 < /tmp/bro-musl.patch \
  && cp /tmp/FindFTS.cmake cmake \
  && cd /tmp/bro/aux/binpac \
  && patch -p1 < /tmp/binpac-musl.patch \
  && echo "===> Compiling bro..." \
  && cd /tmp/bro \
  && CC=clang ./configure --disable-broker \
                          --disable-broctl --disable-broccoli \
                          --disable-auxtools --prefix=/usr/local \
  && make \
  && make install \
  && echo "===> Compiling af_packet plugin..." \
  && cd /tmp/bro/aux/plugins \
  && git clone https://github.com/J-Gras/bro-af_packet-plugin \
  && cd /tmp/bro/aux/plugins/bro-af_packet-plugin \
  && make distclean \
  && CC=clang ./configure --with-kernel=/usr \
  && make \
  && make install \
  && echo "===> Compiling mongodb plugin..." \
  && cd /tmp/bro/aux/plugins \
  && git clone https://github.com/ocmdev/bro-mongodb \ 
  && cd /tmp/bro/aux/plugins/bro-mongodb \
  && make distclean \
  && CC=clang ./configure \
  && make \
  && make install

RUN echo "===> Shrinking image..." \
  && strip -s /usr/local/bin/bro \
  && rm -rf /tmp/* \
  && apk del --purge .build-deps

ENV BROPATH .:/data/config:/usr/local/share/bro:/usr/local/share/bro/policy:/usr/local/share/bro/site

RUN mkdir /root/pcap && mkdir /root/logs

WORKDIR /root/logs

COPY local.bro /usr/local/share/bro/site/local.bro

ENTRYPOINT ["/sbin/tini","--","bro"]
CMD ["-h"]
