open Snkal
open Packet
open Oracle

module Cve_0230 : CLASSIFY = struct
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
    (* Buggy: trusts src_port ∈ {80,443} on inbound without checking it's 
   actually a response. An attacker can spoof src_port=80 to bypass 
   the inbound block on arbitrary dst_ports. *)
  match p.protocol with
  | TCP ->
    List.mem p.dst_port [22; 80; 443]       (* correct check *)
    || List.mem p.src_port [80; 443]         (* BUG: trusts src_port *)
  | _ -> false
end
