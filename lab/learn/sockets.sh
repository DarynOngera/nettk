# Sockets topology tour (Phase 4): ncx/echod, handshake, TIME_WAIT, queues, Nagle.
# shellcheck shell=bash
# Runs on the `basic` fabric: h1 is the client, rtr the server, both on the
# 10.0.1.0/24 link, so the path is one L2 hop and no routing is involved.
# This file defines lesson_main(); run it via lab/wizard.sh sockets.
#
# The echod/ncx steps are skipped until those binaries exist (M1/M4); the kernel
# views (ss, nstat, captures) work at any time.

LESSON_TOPO="basic"
TOPIC="sockets: sockets are kernel objects, not wires"

lesson_main() {
  lesson_start basic "$TOPIC"

  local SRV=10.0.1.1 PORT=9000
  local srv_pid="" log=/tmp/nt-wizard-echod.out

  # start_echo [extra echod args...] -- launch echod on rtr, backgrounded.
  start_echo() {
    stop_echo
    if [[ $LEARN_TEXT == 1 ]]; then
      say "  (text mode: would start echod --bind $SRV --port $PORT $*)"
      return 0
    fi
    nt_ex rtr env NT_LAB=1 "$BIN/echod" --bind "$SRV" --port "$PORT" "$@" \
      >"$log" 2>&1 &
    srv_pid=$!
    sleep 0.3
  }
  stop_echo() {
    if [[ -n $srv_pid ]]; then
      kill "$srv_pid" 2>/dev/null || true
      wait "$srv_pid" 2>/dev/null || true
      srv_pid=""
    fi
  }

  # ---------------------------------------------------------------- 1
  step "A socket is a kernel object, not a wire"
  why <<'EOF'
  Before any byte moves, the kernel already holds the important state: a
  *listening* socket is a struct with a bound local address, a receive queue and
  an accept queue. ss reads exactly that state out of the kernel. Nothing in this
  tour is about cabling; it is about two kernels agreeing on state.
EOF
  predict <<'EOF'
  A server calls listen() and then goes to sleep without ever calling accept().
  A client calls connect() to it. What does connect() return?
  a) an error     b) success: the kernel completed the handshake anyway
  answer b
  because the three-way handshake is finished by the kernel on both ends; the
  finished connection waits in the accept queue until accept() drains it.
EOF
  run rtr ss -ltn
  expect "State" "no listener yet: only the header, no LISTEN rows on rtr"
  note <<'EOF'
  ss -ltn columns: State, Recv-Q, Send-Q, Local Address:Port. For a LISTEN row,
  Recv-Q is the *accept queue length* (completed, unaccepted connections) and
  Send-Q is the backlog limit. That is the queue you will fill in step 6.
EOF

  # ---------------------------------------------------------------- 2
  step "Start echod and watch the listener appear"
  why <<'EOF'
  echod binds an explicit lab address (servers refuse to start without --bind)
  and calls listen(). ss can now see one LISTEN socket. It is single-threaded
  epoll, so every accepted connection is just a slot in a fixed slab plus an
  entry in one epoll set -- no thread per client.
EOF
  if have_tool echod; then
    start_echo
    run rtr ss -ltn
    expect "LISTEN" "the listener is visible in the kernel view"
    expect "9000" "it is bound to the lab port you asked for"
  else
    skip_tool echod "M4"
  fi
  note <<'EOF'
  Send-Q on the LISTEN row is the backlog upper bound, not bytes queued. When you
  later pass --backlog N and run a connect storm, this is the number to read
  against nstat's ListenOverflows.
EOF

  # ---------------------------------------------------------------- 3
  step "Connect, echo, close -- and read the kernel back"
  why <<'EOF'
  ncx connect mode pipes stdin to the socket and the socket to stdout. echod
  echoes whatever it reads. The three views must agree: what ncx printed, what ss
  shows for the two sockets, and what a capture shows on the wire. If they
  disagree, one of your assumptions about the kernel is wrong.
EOF
  if have_tool echod && have_tool ncx; then
    t_run h1 ncx -N -w2 "$SRV" "$PORT"
    run rtr ss -tan
    expect "9000" "the kernel shows the connection (ESTAB or a short-lived row)"
  else
    skip_tool ncx "M1"
  fi
  cmd "capture the same exchange and read the flags"
  if have_tool echod && have_tool ncx; then
    cap rtr r1 10 h1 sh -c 'printf "echo-me" | env NT_LAB=1 '"$BIN"'/ncx -N -w2 '"$SRV"' '"$PORT"
    expect "tcp" "the capture holds the SYN/SYN-ACK/ACK and the FIN/ACK teardown"
  else
    skip_tool ncx "M1"
  fi
  note <<'EOF'
  Read the flags in order: SYN, SYN+ACK, ACK for the handshake; the data segment
  carries PSH+ACK; the close is FIN+ACK from whichever side exits first, then the
  other side's ACK and its own FIN. Relative sequence numbers make the window and
  the ack arithmetic readable.
EOF

  # ---------------------------------------------------------------- 4
  step "TIME_WAIT belongs to whoever closed first"
  why <<'EOF'
  The side that sends the first FIN and receives the final ACK enters TIME_WAIT.
  It lingers for 2*MSL to absorb duplicate segments and to let late packets of
  this connection die before the 4-tuple can be reused. On Linux the timer is
  fixed at 60 s (TCP_TIMEWAIT_LEN); it is not the RFC's configurable knob.
EOF
  predict <<'EOF'
  The server closes first (sends the first FIN). Which side sits in TIME_WAIT?
  a) the client   b) the server
  answer b
  because the side that initiates the close is the one that must absorb the
  remaining segment lifetime; the passive closer just closes when it is done.
EOF
  if have_tool echod && have_tool ncx; then
    t_run rtr ss -tan state time-wait
    note <<'EOF'
    Start echod with a mode that closes after the echo, drive one ncx exchange,
    then re-run this and compare on h1 vs rtr: the TIME_WAIT row appears on the
    side you predicted. Repeat on h1 to see the mirror image.
EOF
  else
    skip_tool echod "M4"
  fi

  # ---------------------------------------------------------------- 5
  step "RST is not an error path, it is a normal one"
  why <<'EOF'
  A reset is the kernel saying "this 4-tuple has no state". You will reproduce it
  three ways: connecting to a closed port (the peer's kernel has no listener, so
  it answers RST), SO_LINGER{1,0} (close sends RST immediately, discarding
  buffered data), and writing to a socket after the peer has fully closed. The
  interesting part is not the RST -- it is what your tool reports for each.
EOF
  cmd "connect to a port nobody listens on: the kernel answers RST"
  if have_tool ncx; then
    t_run h1 ncx -w2 -v "$SRV" 9999
    expect "refus" "connect was refused promptly -- that is a RST, not a timeout"
    cmd "close with RST: --linger0"
    t_run h1 ncx -N --linger0 -w2 "$SRV" "$PORT"
  else
    skip_tool ncx "M1"
  fi
  note <<'EOF'
  A refused connect returns fast with ECONNREFUSED; a filtered port would hang
  until the timeout. That difference (RST vs silence) is the whole basis of port
  scanning in Phase 7.
EOF

  # ---------------------------------------------------------------- 6
  step "The accept queue, and what an overflowing client sees"
  why <<'EOF'
  Completed handshakes wait in the accept queue until accept() drains them, up to
  backlog+1 (capped by net.core.somaxconn). ss shows the current queue in Recv-Q
  and the limit in Send-Q on the LISTEN row. A client whose SYN cannot be queued
  is not told politely: Linux either drops the SYN (client retries, then times
  out) or answers RST depending on tcp_abort_on_overflow.
EOF
  predict <<'EOF'
  echod --backlog 1 runs with --no-accept. A second client connects. What does
  that second client see first?
  a) an immediate RST   b) a completed connect that then stalls   c) a SYN timeout
  answer b
  because backlog+1 connections can finish the handshake; the extra one sits in
  the accept queue, connect() returns 0, and only later is the connection reset
  or dropped when the queue overflows.
EOF
  if have_tool echod; then
    start_echo --backlog 1 --no-accept
    run rtr ss -ltn
    expect "9000" "read Recv-Q (queued) against Send-Q (the limit) while clients pile up"
  else
    skip_tool echod "M4"
  fi
  note <<'EOF'
  After the storm, nstat -az rtr | grep -E 'ListenOverflows|ListenDrops' shows the
  cost of the overflow. The experiment that matters: does raising --backlog move
  the number, and does the client retry or get reset?
EOF
  stop_echo

  # ---------------------------------------------------------------- 7
  step "Nagle, delayed ACK, and why small writes feel slow"
  why <<'EOF'
  Two 1-byte writes back to back do not make two segments. Nagle holds the second
  small segment until the first is ACKed; the receiver's delayed ACK waits about
  40 ms before ACKing. The two algorithms can stall you for ~40 ms. TCP_NODELAY
  disables Nagle; TCP_CORK/MSG_MORE batch the other way, on purpose.
EOF
  predict <<'EOF'
  Without TCP_NODELAY, how long can a second tiny send() wait before it hits the
  wire on Linux?
  a) never, it goes at once   b) about 40 ms   c) about 1 s
  answer b
  because Nagle waits for the ACK of the first segment and delayed ACK waits up to
  ~40 ms to coalesce -- the classic interaction.
EOF
  if have_tool echod && have_tool ncx; then
    start_echo
    cmd "compare two 1-byte writes with and without --nodelay"
    t_run h1 ncx -N --nodelay -w2 "$SRV" "$PORT"
    run rtr ss -ti
    expect "9000" "ss -ti shows srtt/rttvar and cwnd for the connection"
  else
    skip_tool echod "M4"
  fi
  note <<'EOF'
  Measure latency rather than trusting the theory: timestamp the writes in your
  tool, run each variant, and read the inter-segment gap in the capture. Layout vs
  latency is the lesson; the 40 ms is a consequence of two independent algorithms.
EOF
  stop_echo

  # ---------------------------------------------------------------- 8
  step "UDP: datagrams are messages, not a stream"
  why <<'EOF'
  UDP preserves message boundaries: one send() is one datagram, and a recvmsg()
  that is too small truncates and sets MSG_TRUNC -- the rest is gone, never
  retried. A connected UDP socket also surfaces ICMP port-unreachable as
  ECONNREFUSED, but only on a *later* call, because the error arrives after the
  send. An unconnected socket sees nothing.
EOF
  predict <<'EOF'
  You connect a UDP socket to a closed port and call send() twice. Which call
  fails with ECONNREFUSED?
  a) the first   b) the second   c) neither
  answer b
  because the first send() only queues the datagram; the ICMP error comes back
  asynchronously and is delivered to the next operation on the socket.
EOF
  if have_tool echod && have_tool ncx; then
    start_echo
    t_run h1 ncx -u -w2 "$SRV" "$PORT"
    t_run h1 ncx -u -w2 "$SRV" 9999
  else
    skip_tool ncx "M2"
  fi
  note <<'EOF'
  Capture the second case: the ICMP type 3 code 3 that caused ECONNREFUSED is on
  the wire, and our own sniffer decodes it. That link between a socket errno and
  a specific frame is exactly the intuition this lab exists for.
EOF
  stop_echo

  # ---------------------------------------------------------------- 9
  step "Abuse the server: slow clients must not exhaust it"
  why <<'EOF'
  The classic attack on a blocking echo server is a client that sends a lot and
  never reads. echod's answer is backpressure: when a connection's output buffer
  is full it stops reading that connection (drops EPOLLIN, arms EPOLLOUT) instead
  of growing memory or blocking the loop.
EOF
  if have_tool echod; then
    start_echo
    cmd "python3 py/slowclient.py --mode no-read against echod"
    if [[ $LEARN_TEXT != 1 ]]; then
      nt_ex h1 python3 "$root/py/slowclient.py" --host "$SRV" --port "$PORT" \
        --mode no-read --conns 4 --bytes 4194304 --seconds 5 >/tmp/nt-wizard-slow.out 2>&1 &
      local slowpid=$!
      sleep 2
      run rtr ss -tnm
      run rtr sh -c "ls /proc/\$(pgrep -n echod)/fd 2>/dev/null | wc -l"
      expect "9000" "connections to the abusive clients are visible, fds stay bounded"
      wait "$slowpid" 2>/dev/null || true
    fi
  else
    skip_tool echod "M5"
  fi
  stop_echo
  note <<'EOF'
  Run it again and watch echod's RSS and fd count in another shell: both must be
  flat. If memory climbs, the server is buffering instead of applying
  backpressure; if the fd count does not return to baseline, it is leaking.
EOF

  # ---------------------------------------------------------------- 10
  step "Restore, and know where to look next"
  why <<'EOF'
  The narrations above are the M1-M8 experiments. The batch gates (unit tests,
  the flood script, the three-view tables) are the same behaviours without a
  human reading the output -- run them after every change.
EOF
  stop_echo
  cmd "make BUILD=asan test && make san-test"
  cmd "sudo lab/up.sh basic --force"
  note <<'EOF'
  Next: M1 makes ncx transfer 64 MiB both directions with matching sha256; M4
  makes echod survive 100 concurrent clients; M6 reproduces the accept queue and
  TIME_WAIT numbers you just predicted. docs/phase4.md holds the spec these steps
  test.
EOF

  report
}
