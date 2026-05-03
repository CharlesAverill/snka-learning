open Snkal
open Packet
open Oracle

module ExampleFirewall : CLASSIFY = struct
  (*  FORWARD iff ALL of:
      - protocol is TCP, UDP, or ICMP  (no raw/unknown protos)
      - ttl > 0
      - payload_len <= 9000  (no oversized frames)
      - Inbound:  dst_port in {22, 80, 443}
                  src_ip not RFC-1918  (anti-spoof)
      - Outbound: src_port > 1023  (ephemeral only) *)
  let classify p =
    let proto_ok = match p.protocol with Other _ -> false | _ -> true in
    let ttl_ok = p.ttl > 0 in
    let len_ok = p.payload_len <= 9000 in
    let dir_ok =
      match p.direction with
      | Inbound ->
          List.mem p.dst_port [22; 80; 443]
      | Outbound ->
          p.src_port > 1023
    in
    let no_spoof =
      match (p.direction, p.src_ip) with
      | Inbound, (10, _, _, _) ->
          false
      | Inbound, (192, 168, _, _) ->
          false
      | _ ->
          true
    in
    proto_ok && ttl_ok && len_ok && dir_ok && no_spoof
end
