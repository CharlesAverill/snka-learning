open Packet
open Lstar

type policy =
  | Filter of pred
  | Seq of policy * policy
  | Union of policy * policy
  | Star of policy
  | StateGoto of int

let rec string_of_policy = function
  | Filter pr ->
      string_of_pred pr
  | Seq (p, q) ->
      Printf.sprintf "(%s ; %s)" (string_of_policy p) (string_of_policy q)
  | Union (p, q) ->
      Printf.sprintf "(%s + %s)" (string_of_policy p) (string_of_policy q)
  | Star p ->
      Printf.sprintf "(%s)*" (string_of_policy p)
  | StateGoto n ->
      Printf.sprintf "goto(%d)" n

let rec de_morgan_opt = function
  | PAnd (a, b) ->
      let a' = de_morgan_opt a in
      let b' = de_morgan_opt b in
      begin match (a', b') with
      | PTop, x | x, PTop -> x
      | PBot, _ | _, PBot -> PBot
      | _ -> PAnd (a', b')
      end
  | POr (a, b) ->
      let a' = de_morgan_opt a in
      let b' = de_morgan_opt b in
      begin match (a', b') with
      | PTop, _ | _, PTop -> PTop
      | PBot, x | x, PBot -> x
      | _ -> POr (a', b')
      end
  | PNot (PNot x) ->
      de_morgan_opt x
  | p -> p

let opt (p : pred) : pred =
  let x = ref p in
  while !x <> de_morgan_opt !x do
    x := de_morgan_opt !x
  done;
  !x

let rec eval_pred (pr : pred) (pkt : packet) : bool =
  let fst4 (a, _, _, _) = a in
  match pr with
  | PTop ->
      true
  | PBot ->
      false
  | PTest (Proto pr) ->
      pkt.protocol = pr
  | PTest (Dir d) ->
      pkt.direction = d
  | PTest (DstPort n) ->
      pkt.dst_port = n
  | PTest (SrcPort n) ->
      pkt.src_port = n
  | PTest (TTL n) ->
      pkt.ttl = n
  | PTest (PayLen n) ->
      pkt.payload_len = n
  | PTest (SrcIpOct1 n) ->
      fst4 pkt.src_ip = n
  | PAnd (a, b) ->
      eval_pred a pkt && eval_pred b pkt
  | POr (a, b) ->
      eval_pred a pkt || eval_pred b pkt
  | PNot p ->
      not (eval_pred p pkt)

type netkat_automaton =
  { state_count: int
  ; start_state: int
  ; accept_states: int list
  ; delta: (int * pred * int) list
  ; to_policy: int -> policy }

let translate_sfa (a : sfa) : netkat_automaton =
  let indexed = List.mapi (fun i r -> (r, i)) a.states in
  let idx r = List.assoc r indexed in
  let start = idx a.start in
  let accepts = List.map idx a.accepting in
  let delta =
    List.map (fun tr -> (idx tr.src, tr.guard.pred, idx tr.dst)) a.transitions
  in
  let to_policy state_idx =
    let out_edges =
      List.filter_map
        (fun (f, pr, t) ->
          if f = state_idx then
            Some (Seq (Filter pr, StateGoto t))
          else
            None )
        delta
    in
    let base =
      match out_edges with
      | [] ->
          Filter PBot
      | [e] ->
          e
      | e :: es ->
          List.fold_left (fun acc x -> Union (acc, x)) e es
    in
    if List.mem state_idx accepts then
      Union (Filter PTop, base)
    else
      base
  in
  { state_count= List.length a.states
  ; start_state= start
  ; accept_states= accepts
  ; delta
  ; to_policy }

let print_netkat_automaton (na : netkat_automaton) : unit =
  Printf.printf "NetKAT automaton: %d states, start=%d, accept={%s}\n"
    na.state_count na.start_state
    (String.concat "," (List.map string_of_int na.accept_states)) ;
  List.iter
    (fun (f, pr, t) ->
      Printf.printf "  δ(%d, %s) = %d\n" f (string_of_pred pr) t )
    na.delta

(* Serialise a pred to the nkpl predicate syntax  *)
let rec nkpl_of_pred = function
  | PTop ->
      "true"
  | PBot ->
      "∅"
  | PTest (DstPort n) ->
      Printf.sprintf "@dst=%d" n
  | PTest (SrcPort n) ->
      Printf.sprintf "@src=%d" n
  | PTest (TTL n) ->
      Printf.sprintf "@ttl=%d" n
  | PTest (PayLen n) ->
      Printf.sprintf "@len=%d" n
  | PTest (SrcIpOct1 n) ->
      Printf.sprintf "@ip0=%d" n
  | PTest (Proto TCP) ->
      "@proto=6"
  | PTest (Proto UDP) ->
      "@proto=17"
  | PTest (Proto ICMP) ->
      "@proto=1"
  | PTest (Proto (Other n)) ->
      Printf.sprintf "@proto=%d" n
  | PTest (Dir Inbound) ->
      "@dir=0"
  | PTest (Dir Outbound) ->
      "@dir=1"
  | PAnd (a, b) ->
      Printf.sprintf "(%s ∧ %s)" (nkpl_of_pred a) (nkpl_of_pred b)
  | POr (a, b) ->
      Printf.sprintf "(%s ∨ %s)" (nkpl_of_pred a) (nkpl_of_pred b)
  | PNot p ->
      Printf.sprintf "¬%s" (nkpl_of_pred p)

(* Emit a .nkpl file that defines the learned firewall as a NetKAT policy.
   Each state becomes a named filter term; the start state becomes `firewall`.
   Accepting states pass packets through (filter?⋅δ); non-accepting states drop (false?). *)
let emit_nkpl (na : netkat_automaton) (fn : string) : unit =
  let out_fd = open_out fn in
  let print_and_log s =
    Printf.printf "%s" s;
    Out_channel.output_string out_fd s in
  (* Collect outgoing edges per state *)
  let edges_of s =
    List.filter_map
      (fun (f, pr, t) ->
        if f = s then
          Some (pr, t)
        else
          None )
      na.delta
  in
  (* Build the guard for "stay in accept" - the union of all edges that lead
     to an accepting state from the start state.  For the common 2-state
     firewall automaton this is just the single self-loop guard on state 1. *)
  let state_policy s =
    let is_accept = List.mem s na.accept_states in
    let out = edges_of s in
    (* Each outgoing edge: filter the guard, then jump to the target state.
       For a 2-state DFA the target is either self (accept loop) or sink. *)
    let edge_terms =
      List.filter_map
        (fun (pr, t) ->
          if List.mem t na.accept_states then
            (* Edge leads to an accepting state: keep the packet *)
            Some (nkpl_of_pred (opt pr))
          else
            None )
        out
    in
    let accept_pred =
      match edge_terms with
      | [] ->
          if is_accept then
            "true"
          else
            "false"
      | [p] ->
          p
      | ps ->
          String.concat " ∨\n  " ps
    in
    accept_pred
  in
  print_and_log "-- Auto-generated from learned NetKAT automaton\n" ;
  print_and_log (Printf.sprintf "-- %d states, start=%d, accept={%s}\n\n" na.state_count
    na.start_state
    (String.concat "," (List.map string_of_int na.accept_states))) ;
  (* Emit one named predicate per non-sink state *)
  List.iter
    (fun s ->
      if List.mem s na.accept_states then begin
        let pred = state_policy s in
        print_and_log (Printf.sprintf "state%d =\n  %s\n\n" s pred)
      end )
    (List.init na.state_count Fun.id) ;
  (* The top-level firewall policy: filter start state's accept pred, then dup *)
  print_and_log (Printf.sprintf "firewall = state%d?⋅δ\n" na.start_state);
  close_out out_fd
