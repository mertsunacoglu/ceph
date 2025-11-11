FROM almalinux:9

COPY install-deps.sh /
RUN mkdir /src
COPY src/script/ /src/script/
RUN dnf -y install \
        git \
        make \
        gcc \
        dnf-plugins-core \
    && dnf -y update
RUN dnf config-manager --set-enabled plus
RUN dnf config-manager --set-enabled crb
RUN dnf install -y elrepo-release
RUN dnf install -y epel-release
COPY ceph.spec.in /

ENV CCACHE_DIR=/ccache
RUN sh /install-deps.sh
RUN dnf -y install \
        doxygen \
        ccache \
        gcc-c++ \
        jq
