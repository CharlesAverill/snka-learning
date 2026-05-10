FROM ocaml/opam:debian-12-ocaml-5.1

USER root

RUN apt-get update && apt-get install -y \
    git \
    m4 \
    autoconf \
    pkg-config \
    build-essential \
    bubblewrap \
    rsync \
    && rm -rf /var/lib/apt/lists/*

USER opam

WORKDIR /home/opam

RUN git clone --recurse-submodules https://github.com/CharlesAverill/snka-learning.git

WORKDIR /home/opam/snka-learning

RUN opam install -y dune async ego menhir sedlex yojson core async_unix
RUN eval $(opam env) && \
    opam install -y . --deps-only
WORKDIR /home/opam/snka-learning/netkat

RUN eval $(opam env) && \
    opam install -y . --deps-only

WORKDIR /home/opam/snka-learning

RUN eval $(opam env) && \
    dune build -p snkal

# Run the learning and NetKAT verification
CMD ["/bin/bash", "-lc", "eval $(opam env) && ./test.sh"]
