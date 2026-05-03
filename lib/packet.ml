(** Simulated packet structure *)

type protocol = TCP | UDP | ICMP | Other of int

let string_of_protocol = function
  | TCP ->
      "TCP"
  | UDP ->
      "UDP"
  | ICMP ->
      "ICMP"
  | Other n ->
      Printf.sprintf "proto%d" n

type direction = Inbound | Outbound

let string_of_direction = function Inbound -> "IN" | Outbound -> "OUT"

type packet =
  { src_ip: int * int * int * int
  ; dst_ip: int * int * int * int
  ; src_port: int
  ; dst_port: int
  ; protocol: protocol
  ; ttl: int
  ; flags: int
  ; payload_len: int
  ; direction: direction }

let string_of_packet p =
  let a, b, c, d = p.src_ip in
  let e, f, g, h = p.dst_ip in
  Printf.sprintf
    "[%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d %s ttl=%d flags=0x%02x len=%d %s]" a b c
    d p.src_port e f g h p.dst_port
    (string_of_protocol p.protocol)
    p.ttl p.flags p.payload_len
    (string_of_direction p.direction)
