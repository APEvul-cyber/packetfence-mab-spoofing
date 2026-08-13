# MAB identity from Calling-Station-Id can be spoofed on the wire

PacketFence MAB uses Calling-Station-Id from Access-Request. That attribute is not integrity-protected. An on-path attacker can change the MAC and inherit another device's role.

Please do not treat Calling-Station-Id as authentic without Message-Authenticator / a trusted NAS.

See `GITHUB_ISSUE.md`.