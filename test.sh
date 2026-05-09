# Learn the SNKA for the CVE-0230-vulnerable firewall implementation in firewalls/cve_0230.ml

dune exec snkal

# Append a universally-quantified test to the generated firewall rule
echo "-- Is there any inbound TCP packet to a forbidden port
-- that is still accepted by the firewall?

check (
  @dir=0
  ∧ @proto=6
  ∧ ¬(@dst=22 ∨ @dst=80 ∨ @dst=443)
)? ⋅ firewall ≡ drop" >> firewall.nkpl

# Run netkat to find vulnerabilities
cd netkat
dune exec netkat ../firewall.nkpl
