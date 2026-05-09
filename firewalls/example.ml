open Snkal
open Packet
open Oracle

module ExampleFirewall : CLASSIFY = struct
  (* Subtle flaw:
     - Missing SYN check for inbound TCP (allows non-SYN packets)
     - Incomplete RFC1918 filtering (172.16/12 missing)
     - Direction trusted blindly
  *)

  let is_rfc1918 = function
    | 10, _, _, _ ->
        true
    | 192, 168, _, _ ->
        true
    (* BUG: missing 172.16.0.0/12 *)
    | _ ->
        false

  let classify p =
    let proto_ok =
      match p.protocol with TCP | UDP | ICMP -> true | _ -> false
    in
    let ttl_ok = p.ttl > 1 in
    let len_ok = p.payload_len <= 9000 in
    let inbound_ok =
      match p.protocol with
      | TCP ->
          (* BUG: should require SYN, but doesn't *)
          List.mem p.dst_port [22; 80; 443]
      | _ ->
          false
    in
    let outbound_ok = p.src_port > 1023 in
    let dir_ok =
      match p.direction with Inbound -> inbound_ok | Outbound -> outbound_ok
    in
    let no_spoof =
      match p.direction with
      | Inbound ->
          not (is_rfc1918 p.src_ip)
      | Outbound ->
          true
    in
    proto_ok && ttl_ok && len_ok && dir_ok && no_spoof
end
