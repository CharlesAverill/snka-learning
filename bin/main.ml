open Snkal
open Packet
open Oracle
open Lstar
open Netkat
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
    ; direction= Inbound }
  ; (* Additional 30 spot checks *)
    (* FORWARD: Various HTTP/HTTPS combinations *)
    { src_ip= (5, 6, 7, 8)
    ; dst_ip= (10, 0, 0, 1)
    ; src_port= 12345
    ; dst_port= 80
    ; protocol= TCP
    ; ttl= 64
    ; flags= 0x02
    ; payload_len= 1024
    ; direction= Inbound }
  ; { src_ip= (5, 6, 7, 8)
    ; dst_ip= (10, 0, 0, 1)
    ; src_port= 54322
    ; dst_port= 443
    ; protocol= TCP
    ; ttl= 64
    ; flags= 0x02
    ; payload_len= 768
    ; direction= Inbound }
  ; { src_ip= (10, 0, 0, 2)
    ; dst_ip= (8, 8, 8, 8)
    ; src_port= 55001
    ; dst_port= 80
    ; protocol= TCP
    ; ttl= 64
    ; flags= 0x02
    ; payload_len= 512
    ; direction= Outbound }
  ; { src_ip= (10, 0, 0, 3)
    ; dst_ip= (208, 67, 222, 222)
    ; src_port= 56000
    ; dst_port= 443
    ; protocol= TCP
    ; ttl= 64
    ; flags= 0x02
    ; payload_len= 256
    ; direction= Outbound }
  ; { src_ip= (172, 16, 0, 1)
    ; dst_ip= (10, 0, 0, 1)
    ; src_port= 45000
    ; dst_port= 80
    ; protocol= TCP
    ; ttl= 64
    ; flags= 0x02
    ; payload_len= 2048
    ; direction= Inbound }
  ; (* FORWARD: Edge cases with valid flags *)
    { src_ip= (1, 2, 3, 4)
    ; dst_ip= (10, 0, 0, 1)
    ; src_port= 54321
    ; dst_port= 80
    ; protocol= TCP
    ; ttl= 32
    ; flags= 0x02
    ; payload_len= 512
    ; direction= Inbound }
  ; { src_ip= (1, 2, 3, 4)
    ; dst_ip= (10, 0, 0, 1)
    ; src_port= 54321
    ; dst_port= 443
    ; protocol= TCP
    ; ttl= 128
    ; flags= 0x02
    ; payload_len= 256
    ; direction= Inbound }
  ; (* DROP: Invalid sources *)
    { src_ip= (127, 0, 0, 1)
    ; dst_ip= (10, 0, 0, 1)
    ; src_port= 54321
    ; dst_port= 80
    ; protocol= TCP
    ; ttl= 64
    ; flags= 0x02
    ; payload_len= 512
    ; direction= Inbound }
  ; { src_ip= (0, 0, 0, 0)
    ; dst_ip= (10, 0, 0, 1)
    ; src_port= 54321
    ; dst_port= 80
    ; protocol= TCP
    ; ttl= 64
    ; flags= 0x02
    ; payload_len= 512
    ; direction= Inbound }
  ; { src_ip= (255, 255, 255, 255)
    ; dst_ip= (10, 0, 0, 1)
    ; src_port= 54321
    ; dst_port= 80
    ; protocol= TCP
    ; ttl= 64
    ; flags= 0x02
    ; payload_len= 512
    ; direction= Inbound }
  ; (* DROP: Invalid TTL *)
    { src_ip= (1, 2, 3, 4)
    ; dst_ip= (10, 0, 0, 1)
    ; src_port= 54321
    ; dst_port= 80
    ; protocol= TCP
    ; ttl= 1
    ; flags= 0x02
    ; payload_len= 512
    ; direction= Inbound }
  ; { src_ip= (1, 2, 3, 4)
    ; dst_ip= (10, 0, 0, 1)
    ; src_port= 54321
    ; dst_port= 80
    ; protocol= TCP
    ; ttl= 255
    ; flags= 0x00
    ; payload_len= 512
    ; direction= Inbound }
  ; (* DROP: Invalid protocols *)
    { src_ip= (1, 2, 3, 4)
    ; dst_ip= (10, 0, 0, 1)
    ; src_port= 54321
    ; dst_port= 80
    ; protocol= UDP
    ; ttl= 64
    ; flags= 0x00
    ; payload_len= 512
    ; direction= Inbound }
  ; { src_ip= (1, 2, 3, 4)
    ; dst_ip= (10, 0, 0, 1)
    ; src_port= 54321
    ; dst_port= 80
    ; protocol= ICMP
    ; ttl= 64
    ; flags= 0x00
    ; payload_len= 64
    ; direction= Inbound }
  ; { src_ip= (1, 2, 3, 4)
    ; dst_ip= (10, 0, 0, 1)
    ; src_port= 54321
    ; dst_port= 80
    ; protocol= Other 6
    ; ttl= 64
    ; flags= 0x02
    ; payload_len= 512
    ; direction= Inbound }
  ; (* DROP: Invalid payload sizes *)
    { src_ip= (1, 2, 3, 4)
    ; dst_ip= (10, 0, 0, 1)
    ; src_port= 54321
    ; dst_port= 80
    ; protocol= TCP
    ; ttl= 64
    ; flags= 0x02
    ; payload_len= 65536
    ; direction= Inbound }
  ; { src_ip= (1, 2, 3, 4)
    ; dst_ip= (10, 0, 0, 1)
    ; src_port= 54321
    ; dst_port= 80
    ; protocol= TCP
    ; ttl= 64
    ; flags= 0x02
    ; payload_len= 10000
    ; direction= Inbound }
  ; (* DROP: Blocked port range *)
    { src_ip= (1, 2, 3, 4)
    ; dst_ip= (10, 0, 0, 1)
    ; src_port= 54321
    ; dst_port= 22
    ; protocol= TCP
    ; ttl= 64
    ; flags= 0x02
    ; payload_len= 512
    ; direction= Inbound }
  ; { src_ip= (1, 2, 3, 4)
    ; dst_ip= (10, 0, 0, 1)
    ; src_port= 54321
    ; dst_port= 3306
    ; protocol= TCP
    ; ttl= 64
    ; flags= 0x02
    ; payload_len= 512
    ; direction= Inbound }
  ; { src_ip= (1, 2, 3, 4)
    ; dst_ip= (10, 0, 0, 1)
    ; src_port= 54321
    ; dst_port= 5432
    ; protocol= TCP
    ; ttl= 64
    ; flags= 0x02
    ; payload_len= 512
    ; direction= Inbound }
  ; (* FORWARD: Various outbound destinations *)
    { src_ip= (10, 0, 0, 1)
    ; dst_ip= (1, 1, 1, 1)
    ; src_port= 55000
    ; dst_port= 443
    ; protocol= TCP
    ; ttl= 64
    ; flags= 0x02
    ; payload_len= 512
    ; direction= Outbound }
  ; { src_ip= (10, 0, 0, 1)
    ; dst_ip= (4, 4, 4, 4)
    ; src_port= 55001
    ; dst_port= 80
    ; protocol= TCP
    ; ttl= 64
    ; flags= 0x02
    ; payload_len= 256
    ; direction= Outbound }
  ; { src_ip= (10, 0, 0, 1)
    ; dst_ip= (9, 9, 9, 9)
    ; src_port= 55002
    ; dst_port= 443
    ; protocol= TCP
    ; ttl= 64
    ; flags= 0x02
    ; payload_len= 1024
    ; direction= Outbound } ]

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
    ; direction= Inbound }
  ; (* Additional 30 seed packets for better convergence *)
    (* More FORWARD variants *)
    { src_ip= (5, 6, 7, 8)
    ; dst_ip= (10, 0, 0, 1)
    ; src_port= 12345
    ; dst_port= 80
    ; protocol= TCP
    ; ttl= 64
    ; flags= 0x02
    ; payload_len= 1024
    ; direction= Inbound }
  ; { src_ip= (5, 6, 7, 8)
    ; dst_ip= (10, 0, 0, 1)
    ; src_port= 54322
    ; dst_port= 443
    ; protocol= TCP
    ; ttl= 64
    ; flags= 0x02
    ; payload_len= 768
    ; direction= Inbound }
  ; { src_ip= (10, 0, 0, 2)
    ; dst_ip= (8, 8, 8, 8)
    ; src_port= 55001
    ; dst_port= 80
    ; protocol= TCP
    ; ttl= 64
    ; flags= 0x02
    ; payload_len= 512
    ; direction= Outbound }
  ; { src_ip= (10, 0, 0, 3)
    ; dst_ip= (208, 67, 222, 222)
    ; src_port= 56000
    ; dst_port= 443
    ; protocol= TCP
    ; ttl= 64
    ; flags= 0x02
    ; payload_len= 256
    ; direction= Outbound }
  ; { src_ip= (172, 16, 0, 1)
    ; dst_ip= (10, 0, 0, 1)
    ; src_port= 45000
    ; dst_port= 80
    ; protocol= TCP
    ; ttl= 64
    ; flags= 0x02
    ; payload_len= 2048
    ; direction= Inbound }
  ; { src_ip= (10, 0, 0, 1)
    ; dst_ip= (1, 1, 1, 1)
    ; src_port= 55000
    ; dst_port= 443
    ; protocol= TCP
    ; ttl= 64
    ; flags= 0x02
    ; payload_len= 512
    ; direction= Outbound }
  ; { src_ip= (10, 0, 0, 1)
    ; dst_ip= (4, 4, 4, 4)
    ; src_port= 55001
    ; dst_port= 80
    ; protocol= TCP
    ; ttl= 64
    ; flags= 0x02
    ; payload_len= 256
    ; direction= Outbound }
  ; (* Boundary cases and rejections *)
    { src_ip= (1, 2, 3, 4)
    ; dst_ip= (10, 0, 0, 1)
    ; src_port= 54321
    ; dst_port= 22
    ; protocol= TCP
    ; ttl= 64
    ; flags= 0x02
    ; payload_len= 512
    ; direction= Inbound }
  ; { src_ip= (1, 2, 3, 4)
    ; dst_ip= (10, 0, 0, 1)
    ; src_port= 54321
    ; dst_port= 3306
    ; protocol= TCP
    ; ttl= 64
    ; flags= 0x02
    ; payload_len= 512
    ; direction= Inbound }
  ; { src_ip= (1, 2, 3, 4)
    ; dst_ip= (10, 0, 0, 1)
    ; src_port= 54321
    ; dst_port= 5432
    ; protocol= TCP
    ; ttl= 64
    ; flags= 0x02
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
  ; { src_ip= (127, 0, 0, 1)
    ; dst_ip= (10, 0, 0, 1)
    ; src_port= 54321
    ; dst_port= 80
    ; protocol= TCP
    ; ttl= 64
    ; flags= 0x02
    ; payload_len= 512
    ; direction= Inbound }
  ; (* Protocol variants *)
    { src_ip= (1, 2, 3, 4)
    ; dst_ip= (10, 0, 0, 1)
    ; src_port= 54321
    ; dst_port= 80
    ; protocol= UDP
    ; ttl= 64
    ; flags= 0x00
    ; payload_len= 512
    ; direction= Inbound }
  ; { src_ip= (1, 2, 3, 4)
    ; dst_ip= (10, 0, 0, 1)
    ; src_port= 54321
    ; dst_port= 80
    ; protocol= ICMP
    ; ttl= 64
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
  ; (* TTL edge cases *)
    { src_ip= (1, 2, 3, 4)
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
    ; protocol= TCP
    ; ttl= 1
    ; flags= 0x02
    ; payload_len= 512
    ; direction= Inbound }
  ; { src_ip= (1, 2, 3, 4)
    ; dst_ip= (10, 0, 0, 1)
    ; src_port= 54321
    ; dst_port= 80
    ; protocol= TCP
    ; ttl= 255
    ; flags= 0x00
    ; payload_len= 512
    ; direction= Inbound }
  ; (* Payload size variations *)
    { src_ip= (1, 2, 3, 4)
    ; dst_ip= (10, 0, 0, 1)
    ; src_port= 54321
    ; dst_port= 80
    ; protocol= TCP
    ; ttl= 64
    ; flags= 0x00
    ; payload_len= 9001
    ; direction= Inbound }
  ; { src_ip= (1, 2, 3, 4)
    ; dst_ip= (10, 0, 0, 1)
    ; src_port= 54321
    ; dst_port= 80
    ; protocol= TCP
    ; ttl= 64
    ; flags= 0x02
    ; payload_len= 65536
    ; direction= Inbound }
  ; { src_ip= (1, 2, 3, 4)
    ; dst_ip= (10, 0, 0, 1)
    ; src_port= 54321
    ; dst_port= 80
    ; protocol= TCP
    ; ttl= 64
    ; flags= 0x02
    ; payload_len= 10000
    ; direction= Inbound }
  ; (* Broadcast addresses *)
    { src_ip= (0, 0, 0, 0)
    ; dst_ip= (10, 0, 0, 1)
    ; src_port= 54321
    ; dst_port= 80
    ; protocol= TCP
    ; ttl= 64
    ; flags= 0x02
    ; payload_len= 512
    ; direction= Inbound }
  ; { src_ip= (255, 255, 255, 255)
    ; dst_ip= (10, 0, 0, 1)
    ; src_port= 54321
    ; dst_port= 80
    ; protocol= TCP
    ; ttl= 64
    ; flags= 0x02
    ; payload_len= 512
    ; direction= Inbound }
  ; (* Different source ranges for outbound *)
    { src_ip= (10, 0, 0, 2)
    ; dst_ip= (9, 9, 9, 9)
    ; src_port= 55002
    ; dst_port= 443
    ; protocol= TCP
    ; ttl= 64
    ; flags= 0x02
    ; payload_len= 1024
    ; direction= Outbound }
  ; { src_ip= (10, 0, 0, 4)
    ; dst_ip= (8, 8, 8, 8)
    ; src_port= 55003
    ; dst_port= 80
    ; protocol= TCP
    ; ttl= 64
    ; flags= 0x02
    ; payload_len= 256
    ; direction= Outbound }
  ; { src_ip= (10, 0, 0, 5)
    ; dst_ip= (1, 1, 1, 1)
    ; src_port= 55004
    ; dst_port= 443
    ; protocol= TCP
    ; ttl= 64
    ; flags= 0x02
    ; payload_len= 512
    ; direction= Outbound }
  ; { src_ip= (10, 0, 0, 10)
    ; dst_ip= (4, 4, 4, 4)
    ; src_port= 55005
    ; dst_port= 80
    ; protocol= TCP
    ; ttl= 64
    ; flags= 0x02
    ; payload_len= 256
    ; direction= Outbound } ]

let calculate_accuracy sfa test_pkts =
  let total = List.length test_pkts in
  if total = 0 then
    1.0
  else
    let correct =
      List.fold_left
        (fun count pkt ->
          let expected = ExampleFirewall.classify pkt in
          let got = FWLearner.run_sfa sfa [pkt] in
          if expected = got then
            count + 1
          else
            count )
        0 test_pkts
    in
    float_of_int correct /. float_of_int total

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
  let round_counter = ref 0 in
  let equivalence_check (sfa : sfa) : FWLearner.word option =
    incr round_counter ;
    let ax = best_axis () in
    let current_accuracy = calculate_accuracy sfa spot_checks in
    Printf.printf "[Round %d] axis=%s  seeds=%d  accuracy=%.2f%%\n%!"
      !round_counter (axis_name ax)
      (List.length !oracle_seeds)
      (current_accuracy *. 100.0) ;
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
    let singles = List.map (fun p -> [p]) pkts in
    let pairs =
      List.concat_map
        (fun seed -> List.map (fun p -> [seed; p]) !oracle_seeds)
        pkts
    in
    let cex =
      List.find_opt
        (fun w -> FWLearner.mem_query w <> FWLearner.run_sfa sfa w)
        (singles @ pairs)
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
  let sfa =
    FWLearner.run ~max_rounds:30 ~initial_known:seeds equivalence_check
  in
  Printf.printf "\n=== Learned SFA ===\n" ;
  Printf.printf "  States      : %d\n" (List.length sfa.states) ;
  Printf.printf "  Accepting   : %d\n" (List.length sfa.accepting) ;
  Printf.printf "  Transitions : %d\n" (List.length sfa.transitions) ;
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
      let got = FWLearner.run_sfa sfa [pkt] in
      Printf.printf "  [%s] oracle=%-5b hyp=%-5b  %s\n"
        ( if expected = got then
            "OK  "
          else
            "FAIL" )
        expected got (string_of_packet pkt) )
    spot_checks;
  let na = translate_sfa sfa in
  print_netkat_automaton na;
  Printf.printf "\n-- .nkpl output --\n";
  emit_nkpl na
