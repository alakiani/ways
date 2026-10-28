---
status: accepted
---

# An Admin can unlist a domestic Bridge from the Bridge Address

An Admin can **unlist** a domestic Bridge. It leaves the Bridge Address's record and never rejoins on its own, however healthy it is, until the Admin **lists** it again. Everything else about the Node stays: its Links and Paths, carrying other Bridges' traffic across the mesh, and being an Exit for Iran. This amends [ADR 0011](0011-bridge-address.md), where every eligible domestic Bridge is in the record and there are no unpublished spares. Resolved in [Unlisted Bridges](https://github.com/alakiani/ways/issues/115).

## Why

A Bridge can be good in the mesh and bad as an entry. Its provider may be slow or blocked for Users on some ISPs while its Links to the Exits work well, or the Admin may want Users off it before maintenance. Eligibility can't see either: the probe Device passes from the Coordinator.

## How it works

- **Only DNS changes.** An Unlisted Bridge leaves the record at the next round, not after ADR 0011's 60 s. The Node keeps admitting Devices on the Device port, so Devices already on it keep working and drain off as they look the Bridge Address up again (a tunnel toggle, a network change). Nothing is cut off and the Agent does not change.
- **Its eligibility is still judged** while it is unlisted: the probe Device keeps checking it, and the status board shows both.
- **Listing it again** lets it rejoin like any eligible Bridge outside the record, once it has been eligible for the rejoin delay. That time counts through the time it was unlisted, so a healthy Bridge rejoins at the next round.
- **Never empty.** Unlisting is refused unless another domestic Bridge is in the record or eligible now. Inside the loop, ADR 0011's rule still holds: if every member would leave, they all stay, an Unlisted one too.
- **Domestic Bridges only.** The Abroad Bridge Address of [ADR 0014](0014-abroad-devices.md) has no unlisting; unlisting an Abroad Bridge, or a Node that is not a Bridge, is refused.
- **Monitoring:** "Bridge removed from the Bridge Address" ([ADR 0006](0006-monitoring-and-alerting.md)) does not fire for an Unlisted Bridge, which is out by the Admin's choice. "Bridge Address down to one Bridge" still fires: one entry left is one entry left, whatever the reason.

## Considered options

- **Cut Devices off too:** the Node refuses Devices on the Device port, so every Device on it must toggle at once to land elsewhere. Rejected: it drops Users mid-session for what is usually a planned move, and needs an Agent change.
- **Unlisting for both Bridge Addresses:** cheap, but with two Abroad Bridges today there is nothing to choose between.
- **Let the Admin empty the record:** ArvanCloud cannot hold an empty record, so DNS would keep answering with the Unlisted Bridge while the panel says otherwise.
