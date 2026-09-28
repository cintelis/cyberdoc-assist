# CyberDoc Assist

Consent-first remote support for CyberDoc: a technician sees, and with
permission controls, a client's computer from the browser — no software for the
technician to install, a short-lived code the **client** reads out to start it,
a visible "you are being viewed" state, and a tamper-evident log of everything
that happened.

This is the self-hosted / reference implementation. It is **fully
self-contained** — no dependency on any other CyberDoc platform: short-lived
Ed25519-signed grants and a SHA-256 hash-chained audit trail, both implemented
in this repo.

> **Status: proof of concept.** The control plane (codes, signaling, signed
> grants, audit) is built, builds clean, and is smoke-tested. The media/input
> path builds and is wired end to end but needs manual testing with a real
> browser and a few production hardening steps (see *Not done yet*).

## How it works

```
   Client's computer                    Broker (this repo)                Technician
 ┌─────────────────────┐            ┌──────────────────────┐         ┌──────────────────┐
 │ assist-agent (Rust)  │  register  │ /api/sessions → code │         │ browser: viewer  │
 │  screen capture ─────┼───────────►│ /ws/agent            │◄───ws───┤ /ws/viewer       │
 │  H.264 encode        │            │ signs a Grant (Ed25519)│ offer  │ RTCPeerConnection│
 │  input injection ◄───┤            │ hash-chained audit   │────────►│ <video> + input  │
 └─────────┬───────────┘            └──────────────────────┘         └────────┬─────────┘
           │                                                                   │
           └──────────────── WebRTC: H.264 video + control data channel ───────┘
                              (peer to peer — never touches the broker)
```

1. The agent registers a session and gets a **9-digit code**, which the client
   reads to the technician. Nothing starts without it.
2. The technician opens the broker's page, enters the code, and their browser
   makes a WebRTC offer.
3. The broker signs a **grant** (who the technician is, and the most they may
   do — view or control) and relays the offer to the agent. The agent verifies
   the grant against the broker's public key, so a tampered signaling path can't
   widen what the technician is allowed to do.
4. The agent **asks the person at the computer** before streaming, and asks
   again — separately — before allowing control. Input is dropped unless control
   is currently granted (`crates/assist-agent/src/input.rs`).
5. Media and input flow **peer to peer**. The broker only records the events the
   agent reports, in a hash-chained log it cannot silently edit.

## Layout

```
crates/
  assist-proto/    shared wire types; Ed25519-signed session Grant
  assist-broker/   session codes, WebRTC signaling relay, signed grants,
                   SHA-256 hash-chained audit log
  assist-agent/    runs on the client's computer: consent, screen capture,
                   H.264 encode, WebRTC, gated input injection
web/
  viewer.html      the technician's page — plain browser WebRTC, no install
```

### Crypto, self-contained

No external CyberDoc platform is a dependency — this repo owns its trust
primitives, using widely-used permissive crates:

- **Grants** are signed with **Ed25519** (`ed25519-dalek`): the broker holds the
  signing key, serves its public key at `GET /api/key`, and the agent verifies
  every grant against it, so a tampered signaling path cannot widen a
  technician's scope. Grants are short-lived (default 1 hour). See
  `crates/assist-proto/src/lib.rs`.
- **The audit log** is a **SHA-256 hash chain** (`sha2`): each session event is
  one link over the previous hash, so editing, removing or reordering any line
  is detectable. `GET /api/audit` reports `verified: true/false`. See
  `crates/assist-broker/src/audit.rs`.

The workspace `forbid(unsafe_code)`s its own code. Ed25519 is a classical
signature — appropriate for short-lived internal grants; if a post-quantum
posture is later wanted, the grant format is versioned (`cyberdoc.assist.grant.v1`)
so the scheme can be rotated.

## Running it (local, one machine)

```bash
# 1. Start the broker (creates broker-key.seed + audit.jsonl in the cwd)
cargo run -p assist-broker
#    -> listening on http://127.0.0.1:8787

# 2. Start the agent (on the machine to be viewed)
cargo run -p assist-agent
#    -> prints a 9-digit code; asks consent when a technician connects
#    (add --yes-i-own-this-machine to skip the prompts on a machine you own)

# 3. Open http://127.0.0.1:8787 in a browser, enter the code, Connect.
#    Click "Request control" to ask the agent for input control.
```

`GET /api/audit` returns the session log and whether the chain verifies.

## Platform notes

Screen capture uses `xcap`, input injection uses `enigo`; both are
cross-platform, but each OS gates these abilities behind user-granted
permissions — by design, and worth surfacing clearly to the client.

### Windows
Works from a normal user session. To see the UAC (admin-prompt) screen and the
login screen, the agent must run as a Windows service on the secure desktop;
the current binary runs in the user session only.

### macOS — how remote control works here
macOS puts both abilities behind TCC (Transparency, Consent & Control) grants
the user makes in **System Settings -> Privacy & Security**:

- **Screen capture** needs **Screen Recording** permission. `xcap` uses
  CoreGraphics/ScreenCaptureKit under the hood; the first attempt triggers the
  system prompt, and nothing is captured until the user allows it.
- **Input injection** (moving the mouse, typing) needs **Accessibility**
  permission. `enigo` posts `CGEvent`s, which the OS ignores until the app is
  ticked in the Accessibility list.

Practical consequences for shipping on macOS:

- The permission is bound to the **signed binary's identity**, so the app must
  be **code-signed and notarized** (Developer ID). An unsigned/ad-hoc binary
  gets re-prompted or silently denied, and Gatekeeper blocks it on first launch.
- In development, running via `cargo run` means **Terminal (or your IDE)** holds
  the grant — you allow Terminal under Screen Recording and Accessibility once.
- Some things stay off-limits regardless: the login window, other users'
  sessions, and password fields while **Secure Input** is active.
- There is no way to *pre-grant* these silently — which is the point. The
  client makes a deliberate, revocable choice, matching the consent model above.

### iOS / Android (for later)
- **Android:** full control is possible with a native app (MediaProjection for
  capture, AccessibilityService for input); Play Store review of Accessibility
  use is strict.
- **iOS:** third-party remote *control* is not possible; the most Apple allows
  is view-only screen broadcast via a ReplayKit extension. Plan for view-only.

## Security posture

Remote-access tooling is the most abused vector in tech-support scams, so the
consent surface is the product:

- **Client-initiated only** — a short-lived code the client reads out; sessions
  are never pushed to a client.
- **Two separate consents** — one to view, a second to control.
- **Least privilege** — the grant caps what a technician may do; the person can
  always allow less, never more; input is dropped the instant control is not
  granted.
- **Visible + revocable** — the viewer shows a "Viewing / Controlling" state
  (a shipped agent adds a persistent on-screen banner and an end button).
- **Accountable** — every session event is in a hash-chained log; tampering is
  detectable.

## Not done yet

- **Trust the CyberDoc session, not a query string.** The viewer currently sends
  a technician name in the URL; take it from the `cyberdoc_session` cookie and
  set `max_scope` per plan / Cedar policy instead of one broker-wide flag.
- **Anchor the audit head** (sign it, write it to object-locked storage) as
  a signed head written to object-locked storage, so truncation of the tail is
  detectable too.
- **Session/agent expiry**, TURN relay for strict NATs (e.g. Cloudflare
  Realtime), reconnect, and multi-monitor selection.
- **A native consent UI + banner** on the agent, replacing the terminal prompts.
- **Windows service / macOS signed+notarized packaging** per the notes above.
- **Manual end-to-end test** of the media + input path with a real browser.
