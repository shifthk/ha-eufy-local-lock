# eufy Smart Lock (local)

A Home Assistant integration that locks, unlocks and reads a **eufy Smart Lock
T8520P** over your own network. Every lock, unlock and status message goes directly
between Home Assistant and the lock; no add-on, Node.js or Docker is involved.

**What still touches eufy.** The T8520P is a battery lock that switches its Wi-Fi off
between uses and ignores searches on your network while asleep. To wake it, each
connection also sends a wake request through eufy's rendezvous servers, signed with a
wake key that the integration fetches from eufy about once an hour, only when the
cached one has expired. Nothing else is sent to eufy after setup. You can turn the
wake off in the integration's options ("Wake the lock through eufy's servers"); then
nothing goes to eufy at all, but the lock answers only while it happens to be awake.

> **Status: early, working on a T8520P.** Lock, unlock and status work over the LAN
> on one real lock. A press takes about 3 seconds from the button to the new state in
> Home Assistant. It is still young: keep the eufy app (or the keypad) as your way in
> while it proves itself on your door.

## How it works

You sign in to eufy at setup, and the integration fetches what it needs to reach the
lock: its P2P id, the owner and account ids, and its rendezvous servers. These are
kept in the config entry and Home Assistant's private storage. After that:

- **Connection:** Home Assistant opens a P2P session straight to the lock on your LAN,
  using the pure-Python [`eufy-home-security`](https://pypi.org/project/eufy-home-security/)
  library (discovery, handshake, encrypted channel).
- **Commands:** lock, unlock and status use the lock's own command protocol, ported
  from the T8520P path of
  [eufy-security-client](https://github.com/bropat/eufy-security-client). These are
  AES-encrypted BLE-style frames carried in P2P `CMD_SET_PAYLOAD` frames.
- **Session setup:** the lock negotiates no P2P session key (it answers the
  handshake with `-103`). The P2P frames then go in clear, as the eufy app sends
  them. A small runtime patch (`compat.py`) teaches `eufy-home-security` this; the
  lock payload inside stays AES-encrypted.
- **Replies:** the lock confirms a command within about 0.3 s, then pushes its new
  status once the bolt has moved, about 2 s later.
- **Updates:** the lock pushes its own changes (keypad, fingerprint, thumb turn,
  auto-lock) while connected. A periodic check (every 5 minutes by default) also
  reconnects if the link dropped.

Besides the hourly wake key, eufy is needed again only if you add a lock or Home
Assistant's storage is lost. If eufy ends the saved login, you'll get a
re-authentication prompt.

## What you get

| Entity | Notes |
| --- | --- |
| `lock.<name>` | Lock / unlock, with locking, unlocking and jammed states. The attribute `lock_status_code` holds eufy's raw value (3 = unlocked, 4 = locked, 5 = jammed). |
| `sensor.<name>_battery` | Battery %, as reported with every status. |

## Supported

- **eufy Smart Lock T8520P:** the newer T8520 hardware, whose serial is `T8520?9…`,
  with **9** as the seventh character.
- **Other models:** not yet. The same protocol is used by the T8502, T8506, T8510P,
  T85L0, T85V0 and T85P0, so they are the natural next additions. The original
  T8520, R10/R20 and video locks use other command paths.

## Install

**HACS (custom repository):** HACS → ⋮ → Custom repositories, add
`https://github.com/shifthk/ha-eufy-local-lock` as an *Integration*, install
**eufy Smart Lock (local)** and restart Home Assistant.

**Manual:** copy `custom_components/eufy_local_lock` into your config's
`custom_components/`, then restart.

Then go to Settings → Devices & services → Add integration → **eufy Smart Lock (local)**.

## Setup tips

- **Use a second eufy account.** Create a second eufy account, share the lock with it
  from the eufy app, and sign the integration in with that account. Signing in
  elsewhere with the same account (the app, or another integration) ends this
  integration's session.
- **Give the lock a fixed IP** (a DHCP reservation in your router) and enter it at
  setup. Home Assistant and the lock must be on the same LAN segment, with UDP allowed
  between them: no client isolation, no VLAN in between.
- **Running the `eufy_security` integration and its add-on as well?** That's fine,
  but the lock accepts only a few P2P sessions at once. If one side stops answering,
  remove the lock from the other.
- **The lock's Wi-Fi matters most.** A lock that drops off Wi-Fi can't be reached by
  any integration, local or cloud.

## Security notes

- **Credentials:** your eufy password is stored in the config entry, as HA does for
  every integration, so it can sign in again when needed. The cached session and
  keys live in `.storage/eufy_local_lock.<serial>`, which only Home Assistant can read.
- **Commands:** commands are encrypted end to end with a key derived from the lock
  owner's eufy user id. Unlocking from Home Assistant is as safe as your Home
  Assistant: protect it accordingly, and think twice before exposing the lock to
  voice assistants without a PIN.

## Troubleshooting

Enable debug logging for `custom_components.eufy_local_lock` and `eufy_home_security`,
then try a lock / unlock. Download diagnostics from the device page: they show the
P2P session's health counters, with secrets redacted.

## Development

```bash
python -m pytest
```

The `smartlock` package (protocol and client) has no Home Assistant imports and is
tested on its own.

## Credits and license

MIT. The smart-lock protocol is ported from
[bropat/eufy-security-client](https://github.com/bropat/eufy-security-client) (MIT).
The P2P transport is [alaraun/python-eufy-home-security](https://github.com/alaraun/python-eufy-home-security)
(MIT). This project is not affiliated with Anker or eufy. eufy and Anker are
trademarks of Anker Innovations.
