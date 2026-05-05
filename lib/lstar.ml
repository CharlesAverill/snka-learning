open Packet
open Oracle

type field_test =
  | Proto     of protocol
  | Dir       of direction
  | DstPort   of int
  | SrcPort   of int
  | TTL       of int
  | PayLen    of int
  | SrcIpOct1 of int

type pred =
  | PTop
  | PBot
  | PTest of field_test
  | PAnd  of pred * pred
  | POr   of pred * pred
  | PNot  of pred

let rec string_of_pred = function
  | PTop              -> "1"
  | PBot              -> "0"
  | PTest (Proto p)   -> string_of_protocol p
  | PTest (Dir d)     -> string_of_direction d
  | PTest (DstPort n) -> Printf.sprintf "dst=%d" n
  | PTest (SrcPort n) -> Printf.sprintf "src=%d" n
  | PTest (TTL n)     -> Printf.sprintf "ttl=%d" n
  | PTest (PayLen n)  -> Printf.sprintf "len=%d" n
  | PTest (SrcIpOct1 n) -> Printf.sprintf "ip[0]=%d" n
  | PAnd (a, b)       -> Printf.sprintf "(%s ∧ %s)" (string_of_pred a) (string_of_pred b)
  | POr  (a, b)       -> Printf.sprintf "(%s ∨ %s)" (string_of_pred a) (string_of_pred b)
  | PNot p            -> Printf.sprintf "¬%s" (string_of_pred p)

(* A guard pairs a packet predicate function with its NetKAT pred. *)
type guard = { test : packet -> bool; pred : pred }

let guard_true  = { test = (fun _ -> true);  pred = PTop }
let guard_false = { test = (fun _ -> false); pred = PBot }

let guard_and g1 g2 =
  { test = (fun p -> g1.test p && g2.test p)
  ; pred = PAnd (g1.pred, g2.pred) }

let guard_not g =
  { test = (fun p -> not (g.test p))
  ; pred = PNot g.pred }

let guard_or g1 g2 =
  { test = (fun p -> g1.test p || g2.test p)
  ; pred = POr (g1.pred, g2.pred) }

type 'row transition = { src : 'row; guard : guard; dst : 'row }

(** Symbolic DFA *)
type sfa =
  { states      : bool list list
  ; start       : bool list
  ; accepting   : bool list list
  ; transitions : bool list transition list }

let fst4 (a, _, _, _) = a

let atom_guard : field_test -> guard = function
  | Proto pr    -> { test = (fun pk -> pk.protocol    = pr);   pred = PTest (Proto pr) }
  | Dir d       -> { test = (fun pk -> pk.direction   = d);    pred = PTest (Dir d) }
  | DstPort n   -> { test = (fun pk -> pk.dst_port    = n);    pred = PTest (DstPort n) }
  | SrcPort n   -> { test = (fun pk -> pk.src_port    = n);    pred = PTest (SrcPort n) }
  | TTL n       -> { test = (fun pk -> pk.ttl         = n);    pred = PTest (TTL n) }
  | PayLen n    -> { test = (fun pk -> pk.payload_len = n);    pred = PTest (PayLen n) }
  | SrcIpOct1 n -> { test = (fun pk -> fst4 pk.src_ip = n);   pred = PTest (SrcIpOct1 n) }

let atoms_of_packets (pkts : packet list) : field_test list =
  let uniq f xs = List.sort_uniq compare (List.map f xs) in
  List.concat
    [ List.map (fun p -> Proto p)     (uniq (fun p -> p.protocol)    pkts)
    ; List.map (fun d -> Dir d)       (uniq (fun p -> p.direction)   pkts)
    ; List.map (fun n -> DstPort n)   (uniq (fun p -> p.dst_port)    pkts)
    ; List.map (fun n -> SrcPort n)   (uniq (fun p -> p.src_port)    pkts)
    ; List.map (fun n -> TTL n)       (uniq (fun p -> p.ttl)         pkts)
    ; List.map (fun n -> PayLen n)    (uniq (fun p -> p.payload_len) pkts)
    ; List.map (fun n -> SrcIpOct1 n) (uniq (fun p -> fst4 p.src_ip) pkts) ]

let entropy pos neg =
  let p = List.length pos and n = List.length neg in
  let total = p + n in
  if total = 0 then 0.0
  else
    let h x =
      if x = 0 then 0.0
      else let r = float_of_int x /. float_of_int total in -. r *. log r
    in
    h p +. h n

let information_gain (ag : guard) pos neg =
  let pos_t, pos_f = List.partition ag.test pos in
  let neg_t, neg_f = List.partition ag.test neg in
  let total = List.length pos + List.length neg in
  let before = entropy pos neg in
  let wt bp bn =
    let n = List.length bp + List.length bn in
    if n = 0 then 0.0
    else float_of_int n /. float_of_int total *. entropy bp bn
  in
  before -. wt pos_t neg_t -. wt pos_f neg_f

let best_atom atoms pos neg =
  let guards = List.map (fun a -> (a, atom_guard a)) atoms in
  List.fold_left
    (fun (best_a, best_g, best_score) (a, ag) ->
      let score = information_gain ag pos neg in
      if score > best_score then (a, ag, score)
      else (best_a, best_g, best_score))
    (let a0 = List.hd atoms in (a0, atom_guard a0, neg_infinity))
    guards
  |> (fun (a, ag, _) -> (a, ag))

let rec synth_guard (atoms : field_test list) (pos : packet list) (neg : packet list) : guard =
  if pos = [] then guard_false
  else if neg = [] then guard_true
  else if atoms = [] then
    if List.length pos >= List.length neg then guard_true else guard_false
  else begin
    let (a, ag) = best_atom atoms pos neg in
    let atoms'  = List.filter (fun b -> b <> a) atoms in
    let pos_t, pos_f = List.partition ag.test pos in
    let neg_t, neg_f = List.partition ag.test neg in
    let g_t = synth_guard atoms' pos_t neg_t in
    let g_f = synth_guard atoms' pos_f neg_f in
    match g_t.pred, g_f.pred with
    | PBot, PBot -> guard_false
    | PTop, PTop -> guard_true
    | PBot, _    -> guard_and (guard_not ag) g_f
    | _, PBot    -> guard_and ag g_t
    | PTop, _    -> guard_or ag (guard_and (guard_not ag) g_f)
    | _, PTop    -> guard_or (guard_and ag g_t) (guard_not ag)
    | _          -> guard_or (guard_and ag g_t) (guard_and (guard_not ag) g_f)
  end

module Lstar (O : CLASSIFY) = struct

  type word = packet list

  type table =
    { s  : word list
    ; sa : word list
    ; e  : word list
    ; t  : (word * bool list) list }

  let mem_query (w : word) = List.for_all O.classify w

  let fill_row e_list w = List.map (fun e -> mem_query (w @ e)) e_list

  let ensure_row tbl w =
    if List.mem_assoc w tbl.t then tbl
    else { tbl with t = (w, fill_row tbl.e w) :: tbl.t }

  let row tbl w =
    match List.assoc_opt w tbl.t with
    | Some r -> r
    | None   -> fill_row tbl.e w

  let add_experiment tbl new_e =
    if List.mem new_e tbl.e then tbl
    else
      let e_list = tbl.e @ [new_e] in
      let t = List.map (fun (w, _) -> (w, fill_row e_list w)) tbl.t in
      { tbl with e = e_list; t }

  let promote tbl w known_packets =
    let s =
      if List.mem w tbl.s then tbl.s
      else tbl.s @ [w]
    in
    let sa =
      List.fold_left
        (fun acc a ->
          let ext = w @ [a] in
          if List.mem ext acc || List.mem ext s then acc
          else acc @ [ext])
        (List.filter (fun x -> x <> w) tbl.sa)
        known_packets
    in
    let tbl = { tbl with s; sa } in
    let tbl = ensure_row tbl w in
    List.fold_left ensure_row tbl sa

  let find_unclosed tbl =
    let s_rows = List.map (row tbl) tbl.s in
    List.find_opt (fun w -> not (List.mem (row tbl w) s_rows)) tbl.sa

  let find_inconsistency tbl known_packets =
    let pairs =
      let rec aux = function
        | []      -> []
        | x :: xs -> List.map (fun y -> (x, y)) xs @ aux xs
      in
      aux tbl.s
    in
    List.find_map
      (fun (s1, s2) ->
        if row tbl s1 <> row tbl s2 then None
        else
          List.find_map
            (fun a ->
              let r1 = row tbl (s1 @ [a]) in
              let r2 = row tbl (s2 @ [a]) in
              if r1 = r2 then None
              else
                let rec find = function
                  | [], _, _ | _, [], _ | _, _, [] -> None
                  | b1 :: t1, b2 :: t2, e :: te ->
                    if b1 <> b2 then Some ([a] @ e)
                    else find (t1, t2, te)
                in
                find (r1, r2, tbl.e))
            known_packets)
      pairs

  let build_sfa tbl : sfa =
    let s_rows  = List.map (fun s -> (s, row tbl s)) tbl.s in
    let states  = List.sort_uniq compare (List.map snd s_rows) in
    let start   = row tbl [] in
    let accepting =
      List.filter (function b :: _ -> b | [] -> false) states
    in
    let seen_pkts =
      List.filter_map
        (fun (w, _) -> match w with [p] -> Some p | _ -> None)
        tbl.t
    in
    let transitions =
      List.concat_map
        (fun src_row ->
          let src_word =
            match List.find_opt (fun (_, r) -> r = src_row) s_rows with
            | Some (s, _) -> s
            | None        -> []
          in
          let by_dst =
            List.fold_left
              (fun acc pkt ->
                let dst_row = row tbl (src_word @ [pkt]) in
                if not (List.mem dst_row states) then acc
                else
                  let prev = try List.assoc dst_row acc with Not_found -> [] in
                  (dst_row, prev @ [pkt]) :: List.remove_assoc dst_row acc)
              []
              seen_pkts
          in
          let all_pkts = List.concat_map snd by_dst in
          let atoms    = atoms_of_packets all_pkts in
          List.filter_map
            (fun (dst_row, pos) ->
              if pos = [] then None
              else
                let neg = List.filter (fun p -> not (List.mem p pos)) all_pkts in
                let g   = synth_guard atoms pos neg in
                if g.pred = PBot then None
                else Some { src = src_row; guard = g; dst = dst_row })
            by_dst)
        states
    in
    { states; start; accepting; transitions }

  let run_sfa (a : sfa) (w : word) : bool =
    let dead = [] in
    let step state pkt =
      if state = dead then dead
      else
        match
          List.find_opt
            (fun tr -> tr.src = state && tr.guard.test pkt)
            a.transitions
        with
        | Some tr -> tr.dst
        | None    -> dead
    in
    let final = List.fold_left step a.start w in
    List.mem final a.accepting

  let run ?(max_rounds = 100) ?(initial_known : packet list = [])
      (equivalence_check : sfa -> word option) : sfa =
    let init = ensure_row { s = [[]]; sa = []; e = [[]]; t = [] } [] in

    let rec stabilise tbl known =
      match find_unclosed tbl with
      | Some w -> stabilise (promote tbl w known) known
      | None   ->
        match find_inconsistency tbl known with
        | Some new_e -> stabilise (add_experiment tbl new_e) known
        | None       -> tbl
    in

    let rec loop tbl known round =
      if round > max_rounds then (
        Printf.printf "[L*] reached max rounds, returning best hypothesis\n%!";
        build_sfa tbl
      ) else begin
        let tbl = stabilise tbl known in
        Printf.printf "[L*] round %d  |S|=%d |SA|=%d |E|=%d |seen|=%d\n%!"
          round
          (List.length tbl.s) (List.length tbl.sa)
          (List.length tbl.e) (List.length known);
        let hyp = build_sfa tbl in
        Printf.printf "[L*]   conjecture: %d states, %d transitions\n%!"
          (List.length hyp.states)
          (List.length hyp.transitions);
        match equivalence_check hyp with
        | None ->
          Printf.printf "[L*] converged in %d rounds.\n%!" round;
          hyp
        | Some cex ->
          Printf.printf "[L*]   counterexample: length %d\n%!" (List.length cex);
          let new_pkts = List.filter (fun p -> not (List.mem p known)) cex in
          let known'   = known @ new_pkts in
          let suffixes =
            let rec aux acc = function
              | []      -> acc
              | _ :: tl -> aux (tl :: acc) tl
            in
            aux [cex] cex
          in
          let prefixes =
            let rec aux acc pre = function
              | []      -> List.rev (pre :: acc)
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
