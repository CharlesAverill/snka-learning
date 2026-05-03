(** Equivalence classification oracle *)

open Packet

type axis =
  | SrcPort
  | DstPort
  | Protocol
  | TTL
  | PayloadLen
  | Direction
  | SrcIpClass
  | Flags

let all_axes =
  [SrcPort; DstPort; Protocol; TTL; PayloadLen; Direction; SrcIpClass; Flags]

let axis_name = function
  | SrcPort ->
      "src_port"
  | DstPort ->
      "dst_port"
  | Protocol ->
      "protocol"
  | TTL ->
      "ttl"
  | PayloadLen ->
      "payload_len"
  | Direction ->
      "direction"
  | SrcIpClass ->
      "src_ip_class"
  | Flags ->
      "flags"

(* Mutable per-axis stats for UCB bandit *)
type axis_stats =
  { mutable trials: int
  ; mutable hits: int (* mutations that revealed a disagreement *) }

let make_stats () = List.map (fun ax -> (ax, {trials= 0; hits= 0})) all_axes

(* UCB1 score: balance exploitation of productive axes with
   exploration of under-tried ones. *)
let ucb_score total stats =
  if stats.trials = 0 then
    Float.infinity
  else
    let exploit = float_of_int stats.hits /. float_of_int stats.trials in
    let explore =
      sqrt (2.0 *. log (float_of_int total) /. float_of_int stats.trials)
    in
    exploit +. explore

(* Boundary values for each field *)
let src_port_probes = [0; 1; 80; 443; 1023; 1024; 8080; 65535]

let dst_port_probes = [0; 21; 22; 25; 80; 443; 8080; 8443; 65535]

let ttl_probes = [0; 1; 32; 64; 128; 255]

let payload_probes = [0; 1; 64; 1500; 8999; 9000; 9001; 65535]

let flag_probes = [0x00; 0x01; 0x02; 0x04; 0x12; 0x18; 0xFF]

let proto_probes = [TCP; UDP; ICMP; Other 0; Other 253; Other 255]

let dir_probes = [Inbound; Outbound]

let src_ip_probes =
  [ (1, 2, 3, 4)
  ; (* public *)
    (8, 8, 8, 8)
  ; (* public Google DNS *)
    (10, 0, 0, 1)
  ; (* RFC-1918 /8 *)
    (172, 16, 0, 1)
  ; (* RFC-1918 /12 *)
    (192, 168, 1, 1)
  ; (* RFC-1918 /16 *)
    (127, 0, 0, 1)
  ; (* loopback *)
    (0, 0, 0, 0)
  ; (* any *)
    (255, 255, 255, 255) (* broadcast *) ]

(* Generate all mutations of a seed packet along one axis *)
let mutations_for_axis axis pkt =
  match axis with
  | SrcPort ->
      List.map (fun p -> {pkt with src_port= p}) src_port_probes
  | DstPort ->
      List.map (fun p -> {pkt with dst_port= p}) dst_port_probes
  | Protocol ->
      List.map (fun p -> {pkt with protocol= p}) proto_probes
  | TTL ->
      List.map (fun t -> {pkt with ttl= t}) ttl_probes
  | PayloadLen ->
      List.map (fun l -> {pkt with payload_len= l}) payload_probes
  | Direction ->
      List.map (fun d -> {pkt with direction= d}) dir_probes
  | SrcIpClass ->
      List.map (fun i -> {pkt with src_ip= i}) src_ip_probes
  | Flags ->
      List.map (fun f -> {pkt with flags= f}) flag_probes

(* Random packet generator for escaping local clusters *)
let rng = Random.State.make_self_init ()

let random_packet () =
  let rand_ip () =
    ( Random.State.int rng 256
    , Random.State.int rng 256
    , Random.State.int rng 256
    , Random.State.int rng 256 )
  in
  let proto =
    match Random.State.int rng 4 with
    | 0 ->
        TCP
    | 1 ->
        UDP
    | 2 ->
        ICMP
    | _ ->
        Other (Random.State.int rng 256)
  in
  { src_ip= rand_ip ()
  ; dst_ip= rand_ip ()
  ; src_port= Random.State.int rng 65536
  ; dst_port= Random.State.int rng 65536
  ; protocol= proto
  ; ttl= Random.State.int rng 256
  ; flags= Random.State.int rng 256
  ; payload_len= Random.State.int rng 65536
  ; direction=
      ( if Random.State.bool rng then
          Inbound
        else
          Outbound ) }

(* The oracle module type for the smart oracle *)
module type CLASSIFY = sig
  val classify : packet -> bool
end

module SmartOracle (C : CLASSIFY) = struct
  (* State carried across equivalence-check calls *)
  type state =
    { mutable seeds: packet list
    ; axis_stats: (axis * axis_stats) list
    ; mutable total_trials: int
    ; random_rate: int (* 1-in-N chance of adding a random packet *) }

  let make_state seeds =
    {seeds; axis_stats= make_stats (); total_trials= 1; random_rate= 5}

  (* Pick the axis with the highest UCB score *)
  let best_axis st =
    List.fold_left
      (fun (best_ax, best_score) (ax, stats) ->
        let s = ucb_score st.total_trials stats in
        if s > best_score then
          (ax, s)
        else
          (best_ax, best_score) )
      (List.hd all_axes, neg_infinity)
      st.axis_stats
    |> fst

  (* Record whether a mutation on this axis found a disagreement *)
  let record st ax found =
    let stats = List.assoc ax st.axis_stats in
    stats.trials <- stats.trials + 1 ;
    if found then stats.hits <- stats.hits + 1 ;
    st.total_trials <- st.total_trials + 1

  (* Generate candidates for a given axis — used by BFS check below *)
  let mutations_for_seeds ax seeds =
    List.concat_map (mutations_for_axis ax) seeds |> List.sort_uniq compare

  (* Check a single word (list of packets) against hypothesis and oracle *)
  let check_word run_dfa mem_query w = mem_query w <> run_dfa w

  (* Search a candidate list preferring oracle=true/DFA=false, then any mismatch *)
  let find_cex run_dfa mem_query words =
    match List.find_opt (fun w -> mem_query w = true && not (run_dfa w)) words with
    | Some _ as c -> c
    | None -> List.find_opt (check_word run_dfa mem_query) words

  (* Main equivalence check entry point.
     BFS over axes: test all axes at depth-1 (singles) before any depth-2
     (pairs), so the shortest/cheapest counterexample is found first.
     UCB stats are still updated so the axis rankings remain meaningful. *)
  let check st run_dfa mem_query =
    (* Collect mutations for every axis, tagged with which axis produced them *)
    let per_axis =
      List.map
        (fun (ax, _) ->
          let pkts =
            List.concat_map (mutations_for_axis ax) st.seeds
            |> List.sort_uniq compare
          in
          (ax, pkts) )
        st.axis_stats
    in
    (* BFS level 1: singles from every axis *)
    let all_singles =
      List.concat_map (fun (_, pkts) -> List.map (fun p -> [p]) pkts) per_axis
      |> List.sort_uniq compare
    in
    (* BFS level 2: seed × mutant pairs from every axis *)
    let all_pairs =
      List.concat_map
        (fun (_, pkts) ->
          List.concat_map (fun seed -> List.map (fun p -> [seed; p]) pkts) st.seeds )
        per_axis
      |> List.sort_uniq compare
    in
    (* Also sprinkle randoms at both levels *)
    let n_rand = (List.length all_singles / st.random_rate) + 1 in
    let randoms = List.init n_rand (fun _ -> random_packet ()) in
    let rand_singles = List.map (fun p -> [p]) randoms in
    let rand_pairs =
      List.concat_map (fun seed -> List.map (fun p -> [seed; p]) randoms) st.seeds
    in
    (* Test every seed as a single word first, before any mutations.
       This ensures the DFA is checked against all known-interesting packets
       before we start exploring neighbours. *)
    let seed_singles = List.map (fun p -> [p]) st.seeds in
    let all_words = seed_singles @ all_singles @ rand_singles @ all_pairs @ rand_pairs in
    let cex = find_cex run_dfa mem_query all_words in
    (* Update UCB stats: credit whichever axis the counterexample came from *)
    let cex_pkts = Option.fold ~none:[] ~some:(fun w -> w) cex in
    List.iter
      (fun (ax, pkts) ->
        let hit =
          Option.is_some cex
          && List.exists (fun p -> List.mem p pkts) cex_pkts
        in
        record st ax hit )
      per_axis ;
    (* Widen seed set *)
    ( match cex with
    | Some w ->
        let new_seeds = List.filter (fun p -> not (List.mem p st.seeds)) w in
        st.seeds <- st.seeds @ new_seeds
    | None ->
        let r = random_packet () in
        if not (List.mem r st.seeds) then st.seeds <- st.seeds @ [r] ) ;
    cex

  (* Convenience: wrap state in a closure suitable for Lstar.run *)
  let make_check_fn seeds =
    let st = ref (make_state seeds) in
    fun dfa ->
      (* We need access to run_dfa and mem_query from outside the functor,
         so those are passed in via partial application at call site.
         Here we just return the oracle state for external wiring. *)
      ignore dfa ; st
  (* see wiring in main below *)
end
