---
status: accepted
---

# No OpenVPN over TCP for Devices: a field test on Irancell cellular showed the filter learns it within hours

We considered OpenVPN over TCP, through the stock OpenVPN Connect app, as a second way for Devices to reach a Bridge alongside WireGuard. The aim was to reach Bridges whose provider blocks WireGuard or UDP on mobile carriers, the accepted cost in [ADR 0011](0011-bridge-address.md). We decided **not to build it**. A field test on Irancell cellular showed a stock OpenVPN tunnel bought hours, not a lasting fix. Resolved in [Field-test stock OpenVPN over TCP from MCI and Irancell](https://github.com/alakiani/ways/issues/102), the gate of the [OpenVPN over TCP map](https://github.com/alakiani/ways/issues/101).

## What the test showed

Every domestic Bridge, plus a new Bridge on Irancell Cloud, ran throwaway `openvpn` 2.7 listeners with `tls-crypt-v2` on TCP 443 and 31194. One phone, on Irancell cellular and on Wi-Fi, on 2026-10-25:

- **Over Wi-Fi, and Bridge to Bridge, every listener worked.** The servers and profiles were sound.
- **On Irancell cellular, port 443 failed on every Bridge tried.** The handshake completed and then the flow was held and starved.
- **The high port worked on two of four Bridges**, including parvaz-bridge-03, where WireGuard is blocked on that carrier. **About 3.5 hours later the same Bridge and port were starved:** handshake round trips of 1 to 11 s, and key negotiation never finished.
- **omid-bridge-04 was starved on both ports from the start.** **irancell-bridge-05 was unreachable for WireGuard and OpenVPN alike:** not one SYN from Irancell's mobile network reached the VM.

So the filtering applies inside Iran, varies by carrier and destination provider, and adapts to traffic that behaves like a tunnel. OpenVPN can be fingerprinted even with `tls-crypt` (research on [What does stock OpenVPN Connect support](https://github.com/alakiani/ways/issues/103)), so a stock OpenVPN tunnel is exactly what such a filter learns. MCI was not tested. We decided without it, because a protocol the filter learns within hours on one major carrier is not worth a second credential model, Bridge daemon and issuance path.

## Considered options

- **Build OpenVPN with the high port first and 443 left out:** rejected for the reason above.
- **Wait for the MCI results:** declined. A pass on MCI would not undo what Irancell showed.

## Consequences

- WireGuard stays the only way a Device connects. The glossary keeps **Device** as one WireGuard keypair.
- The browser-side OpenVPN key research ([#104](https://github.com/alakiani/ways/issues/104)) stays on its research branch, in case a later effort needs certificates made in the browser.
- The test's real finding is **which Bridges each carrier can reach, and for how long**. It affects WireGuard as much as it would have affected OpenVPN, and it is left to a separate effort. The Coordinator's probe runs from outside the carriers, so a Bridge that a carrier cannot reach stays in the Bridge Address.
