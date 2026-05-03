(** Implementation of the L* algorithm *)

open Packet
open Oracle

module Lstar (O : CLASSIFY) = struct
  (** A word over Sigma is a finite sequence of packets. *)
  type word = packet list

  (** Observation Table
      Rows are words (prefixes in S, or S-extensions in SA).
      Columns are words (suffix experiments in E).
      Entry T(w, e) = classify(w . e).

      Because Sigma is infinite, S and SA are built up only from
      packets seen in counterexamples; they start with just
      the empty word. *)
  type table =
    {s: word list; sa: word list; e: word list; t: (word * bool list) list}

  (** A DFA state is identified by its observation row. *)
  type dfa =
    { states: bool list list
    ; start: bool list
    ; accepting: bool list list
    ; transitions: (bool list * packet * bool list) list }

  (** A word is accepted if every packet in it is forwarded *)
  let mem_query (w : word) : bool = List.for_all O.classify w

  let fill_row (e_list : word list) (w : word) : bool list =
    List.map (fun e -> mem_query (w @ e)) e_list

  let ensure_row tbl w =
    if List.mem_assoc w tbl.t then
      tbl
    else
      {tbl with t= (w, fill_row tbl.e w) :: tbl.t}

  let row tbl w =
    match List.assoc_opt w tbl.t with
    | Some r ->
        r
    | None ->
        fill_row tbl.e w (* fallback; table should be complete *)

  (** Add a new experiment column, recomputing all existing rows. *)
  let add_experiment tbl new_e =
    if List.mem new_e tbl.e then
      tbl
    else
      let e_list = tbl.e @ [new_e] in
      let t = List.map (fun (w, _) -> (w, fill_row e_list w)) tbl.t in
      {tbl with e= e_list; t}

  (** Promote a word into S, extending SA with one-packet extensions
      drawn from the set of packets seen so far. *)
  let promote tbl w known_packets =
    let s =
      if List.mem w tbl.s then
        tbl.s
      else
        tbl.s @ [w]
    in
    let sa =
      List.fold_left
        (fun acc a ->
          let ext = w @ [a] in
          if List.mem ext acc || List.mem ext s then
            acc
          else
            acc @ [ext] )
        (List.filter (fun x -> x <> w) tbl.sa)
        known_packets
    in
    let tbl = {tbl with s; sa} in
    let tbl = ensure_row tbl w in
    List.fold_left ensure_row tbl sa

  let find_unclosed tbl =
    let s_rows = List.map (row tbl) tbl.s in
    List.find_opt (fun w -> not (List.mem (row tbl w) s_rows)) tbl.sa

  let find_inconsistency tbl known_packets =
    let pairs =
      let rec aux = function
        | [] ->
            []
        | x :: xs ->
            List.map (fun y -> (x, y)) xs @ aux xs
      in
      aux tbl.s
    in
    List.find_map
      (fun (s1, s2) ->
        if row tbl s1 <> row tbl s2 then
          None
        else
          List.find_map
            (fun a ->
              let r1 = row tbl (s1 @ [a]) in
              let r2 = row tbl (s2 @ [a]) in
              if r1 = r2 then
                None
              else
                let rec find = function
                  | [], _, _ | _, [], _ | _, _, [] ->
                      None
                  | b1 :: t1, b2 :: t2, e :: te ->
                      if b1 <> b2 then
                        Some ([a] @ e)
                      else
                        find (t1, t2, te)
                in
                find (r1, r2, tbl.e) )
            known_packets )
      pairs

  let build_dfa tbl : dfa =
    let s_rows = List.map (fun s -> (s, row tbl s)) tbl.s in
    let states = List.sort_uniq compare (List.map snd s_rows) in
    let start = row tbl [] in
    let accepting =
      List.filter (fun r -> match r with b :: _ -> b | [] -> false) states
    in
    let seen_pkts =
      List.filter_map
        (fun (w, _) -> match w with [p] -> Some p | _ -> None)
        tbl.t
    in
    let transitions =
      List.concat_map
        (fun r ->
          let s = fst (List.find (fun (_, r') -> r' = r) s_rows) in
          List.filter_map
            (fun a ->
              let dest = row tbl (s @ [a]) in
              if List.mem dest states then
                Some (r, a, dest)
              else
                None )
            seen_pkts )
        states
    in
    {states; start; accepting; transitions}

  let run_dfa dfa (w : word) : bool =
    let dead = [] in
    let step state a =
      if state = dead then dead
      else
        match List.find_opt (fun (s, p, _) -> s = state && p = a) dfa.transitions with
        | Some (_, _, t) -> t
        | None -> dead
    in
    let final = List.fold_left step dfa.start w in
    List.mem final dfa.accepting

  let run ?(max_rounds = 100) ?(initial_known : packet list = []) (equivalence_check : dfa -> word option) : dfa =
    (* [equivalence_check hyp] should return [None] if the hypothesis
       DFA agrees with O.classify on all words, or [Some counterexample]
       (a word where they disagree) otherwise. *)
    (* Bootstrap: S = {[]}, SA = {}, E = {[]} *)
    let init = ensure_row {s= [[]]; sa= []; e= [[]]; t= []} [] in
    (* Bring the table to a closed, consistent state without counting rounds.
       Each call to [stabilise] does as many close/consistency steps as needed
       before returning a table ready for a conjecture. *)
    let rec stabilise tbl known =
      match find_unclosed tbl with
      | Some w -> stabilise (promote tbl w known) known
      | None -> (
        match find_inconsistency tbl known with
        | Some new_e -> stabilise (add_experiment tbl new_e) known
        | None -> tbl )
    in
    let rec loop tbl known round =
      if round > max_rounds then (
        Printf.printf "[L*] reached max rounds, returning best hypothesis\n%!" ;
        build_dfa tbl
      ) else begin
        let tbl = stabilise tbl known in
        Printf.printf "[L*] round %d  |S|=%d |SA|=%d |E|=%d |seen|=%d\n%!" round
          (List.length tbl.s) (List.length tbl.sa) (List.length tbl.e)
          (List.length known) ;
        let hyp = build_dfa tbl in
        Printf.printf "[L*]   conjecture: %d states, %d transitions\n%!"
          (List.length hyp.states) (List.length hyp.transitions) ;
        match equivalence_check hyp with
        | None ->
            Printf.printf "[L*] converged in %d rounds.\n%!" round ;
            hyp
        | Some cex ->
            Printf.printf "[L*]   counterexample: length %d\n%!" (List.length cex) ;
            (* Both steps are needed together:
               - Suffixes into E: give the table columns that can discriminate
                 why packets differ (drives |E| growth and state splitting).
               - Prefixes into S via promote: give the table rows for those
                 columns to actually split (drives |S| growth).
               Without suffixes, |E| stays 1 and the DFA never grows past 2 states.
               Without prefixes, |S| stays 1 and SA stays empty so promote never
               fires and known never populates the table. *)
            let new_pkts = List.filter (fun p -> not (List.mem p known)) cex in
            let known' = known @ new_pkts in
            let suffixes =
              let rec aux acc = function
                | [] -> acc
                | _ :: tl -> aux (tl :: acc) tl
              in
              aux [cex] cex
            in
            let prefixes =
              let rec aux acc pre = function
                | [] -> List.rev (pre :: acc)
                | x :: xs -> aux (pre :: acc) (pre @ [x]) xs
              in
              aux [] [] cex
            in
            let tbl = List.fold_left add_experiment tbl suffixes in
            let tbl = List.fold_left (fun t w -> promote t w known') tbl prefixes in
            loop tbl known' (round + 1)
      end
    in
    loop init initial_known 1
end
