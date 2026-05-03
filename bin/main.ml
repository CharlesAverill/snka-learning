open Snkal
open Packet
open Oracle
open Lstar
open Firewalls
open Example
module FWLearner = Lstar (ExampleFirewall)

let spot_checks =
  [ (* Should FORWARD *)
    { src_ip= (1, 2, 3, 4)
    ; dst_ip= (10, 0, 0, 1)
    ; src_port= 54321
    ; dst_port= 80
    ; protocol= TCP
    ; ttl= 64
    ; flags= 0x02
    ; payload_len= 512
    ; direction= Inbound }
  ; { src_ip= (1, 2, 3, 4)
    ; dst_ip= (10, 0, 0, 1)
    ; src_port= 54321
    ; dst_port= 443
    ; protocol= TCP
    ; ttl= 64
    ; flags= 0x02
    ; payload_len= 512
    ; direction= Inbound }
  ; { src_ip= (10, 0, 0, 1)
    ; dst_ip= (8, 8, 8, 8)
    ; src_port= 55000
    ; dst_port= 443
    ; protocol= TCP
    ; ttl= 64
    ; flags= 0x02
    ; payload_len= 256
    ; direction= Outbound }
  ; (* Should DROP *)
    { src_ip= (1, 2, 3, 4)
    ; dst_ip= (10, 0, 0, 1)
    ; src_port= 54321
    ; dst_port= 8080
    ; protocol= TCP
    ; ttl= 64
    ; flags= 0x00
    ; payload_len= 512
    ; direction= Inbound }
  ; { src_ip= (192, 168, 1, 1)
    ; dst_ip= (10, 0, 0, 1)
    ; src_port= 54321
    ; dst_port= 80
    ; protocol= TCP
    ; ttl= 64
    ; flags= 0x02
    ; payload_len= 256
    ; direction= Inbound }
  ; { src_ip= (1, 2, 3, 4)
    ; dst_ip= (10, 0, 0, 1)
    ; src_port= 54321
    ; dst_port= 80
    ; protocol= TCP
    ; ttl= 0
    ; flags= 0x00
    ; payload_len= 64
    ; direction= Inbound }
  ; { src_ip= (1, 2, 3, 4)
    ; dst_ip= (10, 0, 0, 1)
    ; src_port= 54321
    ; dst_port= 80
    ; protocol= Other 253
    ; ttl= 64
    ; flags= 0x00
    ; payload_len= 64
    ; direction= Inbound }
  ; { src_ip= (1, 2, 3, 4)
    ; dst_ip= (10, 0, 0, 1)
    ; src_port= 54321
    ; dst_port= 80
    ; protocol= TCP
    ; ttl= 64
    ; flags= 0x00
    ; payload_len= 9001
    ; direction= Inbound } ]

(* Seed packets: a small diverse starting set *)
let seeds : packet list =
  [ (* Forwarded: inbound HTTP *)
    { src_ip= (1, 2, 3, 4)
    ; dst_ip= (10, 0, 0, 1)
    ; src_port= 54321
    ; dst_port= 80
    ; protocol= TCP
    ; ttl= 64
    ; flags= 0x02
    ; payload_len= 512
    ; direction= Inbound }
  ; (* Forwarded: outbound ephemeral *)
    { src_ip= (10, 0, 0, 1)
    ; dst_ip= (8, 8, 8, 8)
    ; src_port= 55000
    ; dst_port= 443
    ; protocol= TCP
    ; ttl= 64
    ; flags= 0x02
    ; payload_len= 256
    ; direction= Outbound }
  ; (* Dropped: inbound to a blocked port - gives the oracle a reject example
       from the very first round so it can find the accept/reject boundary *)
    { src_ip= (1, 2, 3, 4)
    ; dst_ip= (10, 0, 0, 1)
    ; src_port= 54321
    ; dst_port= 8080
    ; protocol= TCP
    ; ttl= 64
    ; flags= 0x00
    ; payload_len= 512
    ; direction= Inbound } ]

let () =
  (* Mutable oracle state *)
  let axis_stats = make_stats () in
  let oracle_seeds = ref seeds in
  let total_trials = ref 1 in
  let random_rate = 5 in
  let best_axis () =
    List.fold_left
      (fun (best_ax, best_score) (ax, stats) ->
        let s = ucb_score !total_trials stats in
        if s > best_score then
          (ax, s)
        else
          (best_ax, best_score) )
      (List.hd all_axes, neg_infinity)
      axis_stats
    |> fst
  in
  let record ax found =
    let stats = List.assoc ax axis_stats in
    stats.trials <- stats.trials + 1 ;
    if found then stats.hits <- stats.hits + 1 ;
    total_trials := !total_trials + 1
  in
  let equivalence_check (dfa : FWLearner.dfa) : FWLearner.word option =
    let ax = best_axis () in
    Printf.printf "[oracle] axis=%s  seeds=%d\n%!" (axis_name ax)
      (List.length !oracle_seeds) ;
    let known_pkts =
      List.filter_map (fun (_, p, _) -> Some p) dfa.transitions
      |> List.sort_uniq compare
    in
    let mutated =
      List.concat_map (mutations_for_axis ax) !oracle_seeds
      |> List.sort_uniq compare
    in
    let randoms =
      List.init
        ((List.length mutated / random_rate) + 1)
        (fun _ -> random_packet ())
    in
    let pkts = mutated @ randoms in
    (* Check known packets against the DFA *)
    let known_only = List.filter (fun p -> List.mem p known_pkts) pkts in
    let singles = List.map (fun p -> [p]) known_only in
    let pairs =
      List.concat_map
        (fun seed -> List.map (fun p -> [seed; p]) !oracle_seeds)
        known_only
    in
    let known_cex =
      List.find_opt
        (fun w -> FWLearner.mem_query w <> FWLearner.run_dfa dfa w)
        (singles @ pairs)
    in
    (* If no known counterexample, look for an unknown accepted packet *)
    let cex =
      match known_cex with
      | Some _ ->
          known_cex
      | None ->
          let unknown_accepted =
            List.find_opt
              (fun p -> (not (List.mem p known_pkts)) && FWLearner.mem_query [p])
              pkts
          in
          Option.map (fun p -> [p]) unknown_accepted
    in
    record ax (Option.is_some cex) ;
    ( match cex with
    | Some w ->
        let new_pkts =
          List.filter (fun p -> not (List.mem p !oracle_seeds)) w
        in
        oracle_seeds := !oracle_seeds @ new_pkts
    | None ->
        let r = random_packet () in
        if not (List.mem r !oracle_seeds) then
          oracle_seeds := !oracle_seeds @ [r] ) ;
    cex
  in
  Printf.printf "=== L* firewall learner with smart oracle ===\n%!" ;
  let dfa =
    FWLearner.run ~max_rounds:10 ~initial_known:seeds equivalence_check
  in
  Printf.printf "\n=== Learned DFA ===\n" ;
  Printf.printf "  States      : %d\n" (List.length dfa.states) ;
  Printf.printf "  Accepting   : %d\n" (List.length dfa.accepting) ;
  Printf.printf "  Transitions : %d\n" (List.length dfa.transitions) ;
  Printf.printf "\n=== Axis productivity ===\n" ;
  List.iter
    (fun (ax, stats) ->
      Printf.printf "  %-14s  trials=%d  hits=%d  rate=%.2f\n" (axis_name ax)
        stats.trials stats.hits
        ( if stats.trials = 0 then
            0.0
          else
            float_of_int stats.hits /. float_of_int stats.trials ) )
    axis_stats ;
  Printf.printf "\n=== Spot checks ===\n" ;
  List.iter
    (fun pkt ->
      let expected = ExampleFirewall.classify pkt in
      let got = FWLearner.run_dfa dfa [pkt] in
      Printf.printf "  [%s] oracle=%-5b hyp=%-5b  %s\n"
        ( if expected = got then
            "OK  "
          else
            "FAIL" )
        expected got (string_of_packet pkt) )
    spot_checks
