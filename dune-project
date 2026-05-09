(lang dune 3.9)

(name snkal)

(generate_opam_files true)

(source
 (github CharlesAverill/snkal))

(authors "CharlesAverill")

(maintainers "CharlesAverill")

(license MIT)

(documentation https://github.com/CharlesAverill/snkal)

(package
 (name snkal)
 (synopsis "Learning symbolic NetKAT automata from simulated firewalls")
 (description "Learning symbolic NetKAT automata from simulated firewalls using the L* algorithm")
 (depends ocaml dune ocamlformat))

