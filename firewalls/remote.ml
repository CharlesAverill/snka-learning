(** Sends a binary-encoded packet to a remote process at a predefined address
    and port, expects either FWD or DRP as a response.

    Binary wire format (13 bytes, all big-endian):
      Offset  Size  Field
      0       1     protocol   (uint8: TCP=6, UDP=17, ICMP=1, Other=n)
      1       1     direction  (uint8: Inbound=0, Outbound=1)
      2       2     src_port   (uint16)
      4       2     dst_port   (uint16)
      6       1     ttl        (uint8)
      7       2     payload_len (uint16)
      9       1     src_ip[0]  (uint8)
      10      1     src_ip[1]  (uint8)
      11      1     src_ip[2]  (uint8)
      12      1     src_ip[3]  (uint8)
*)
open Snkal
open Packet
open Oracle
open Unix

module type FirewallCfg = sig
  val addr : string
  val port : int
end

module RemoteFirewall (Cfg : FirewallCfg) : CLASSIFY = struct

  (** Encode a packet as a 13-byte big-endian binary buffer. *)
  let encode_packet (p : packet) : bytes =
    let buf = Bytes.create 13 in
    let proto_num =
      match p.protocol with
      | TCP     -> 6
      | UDP     -> 17
      | ICMP    -> 1
      | Other n -> n
    in
    let dir_num =
      match p.direction with
      | Inbound  -> 0
      | Outbound -> 1
    in
    let (a, b, c, d) = p.src_ip in
    (* uint8 fields *)
    Bytes.set_uint8 buf 0  proto_num;
    Bytes.set_uint8 buf 1  dir_num;
    (* uint16 big-endian fields *)
    Bytes.set_uint16_be buf 2 p.src_port;
    Bytes.set_uint16_be buf 4 p.dst_port;
    (* uint8 fields *)
    Bytes.set_uint8 buf 6  p.ttl;
    (* uint16 big-endian *)
    Bytes.set_uint16_be buf 7 p.payload_len;
    (* src_ip octets *)
    Bytes.set_uint8 buf 9  a;
    Bytes.set_uint8 buf 10 b;
    Bytes.set_uint8 buf 11 c;
    Bytes.set_uint8 buf 12 d;
    buf

  (** Send a binary-encoded packet to the remote oracle and read its response. *)
  let query_remote (msg : bytes) : bool =
    let sock = socket PF_INET SOCK_STREAM 0 in
    let addr = ADDR_INET (inet_addr_of_string Cfg.addr, Cfg.port) in
    connect sock addr;
    (* Send exactly 13 bytes — no newline delimiter needed. *)
    let oc = out_channel_of_descr sock in
    output_bytes oc msg;
    flush oc;
    (* Read a 3-byte response: "FWD" or "DRP". *)
    let ic = in_channel_of_descr sock in
    let response =
      try
        let buf = Bytes.create 3 in
        really_input ic buf 0 3;
        Bytes.to_string buf
      with End_of_file -> "DRP"
    in
    close sock;
    match response with
    | "FWD" -> true
    | "DRP" -> false
    | _     -> false

  let classify (p : packet) : bool =
    let msg = encode_packet p in
    query_remote msg

end
