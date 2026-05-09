# snkal

Learning symbolic NetKAT automata from simulated firewalls using the L* algorithm

## Installation and Usage

A [Dockerfile](./Dockerfile) is provided to bypass manual installation:

```
docker build -t snkal .
docker run --rm snkal
```

Requires [dune](https://dune.build/install) and [opam](https://opam.ocaml.org/doc/Install.html) to build and install dependencies.

```
git clone https://github.com/CharlesAverill/snka-learning.git --recurse-submodules
cd snka-learning

opam switch create snkal
opam install . --deps-only
cd netkat
opam install . --deps-only
cd ..

dune build
```

Now run `./test.sh` to run the learning algorithm on an implementation of a firewall containing an [IP spoofing vulnerability](firewalls/cve_0230.ml).
After learning the firewall DFA, [NetKAT](https://netkat.org/) will be search for malformed packets that make it through the firewall, and will find the following:

```
>>> Check FAILED. <<< (expected: (@dir=0 & @proto=6 & ¬(@dst=22 ∪ @dst=80 ∪ @dst=443))⋅firewall ≡ drop)
Counterexample trace:
[@proto=6,@dst=9000,@dir=0];[@proto=6,@dst=9000,@dir=0];[@proto=6,@dst=9000,@dir=0]
```

An inbound TCP packet is found that makes it to a forbidden port by spoofing its IP address.
