# Ten rules for governing AI agents

I run a team of AI coding agents on one Mac to build a safety product: radio nodes that get alerts to phones when cell and Wi-Fi are down. Running agents unsupervised for weeks taught me that **written instructions alone don't hold**. Every rule below exists because something went wrong without it, and each one is enforced by a mechanism, not a prompt.

1. **People's data stays with people.** Agents get counts and hashes, never message bodies, names or locations.
2. **Life-safety never waits on the AI.** Anything that protects a person runs on site, without the cloud or an agent in the path.
3. **Humans set the goal.** The goal is signed by a person and an agent can't change it; every proposal states its effect on the goal.
4. **Test before you claim.** No result counts without evidence from a test at the worst end of every range.
5. **Ask, don't guess.** "I need X to continue" is a valid answer, not a failure.
6. **Corrections bind.** When a human corrects an agent, the correction blocks conflicting work until it's lifted.
7. **Keep an honest record.** An append-only log of decisions, results and the agent's own mistakes with their causes, reloaded at the start of every session.
8. **Learn openly.** Mistakes become test cases; lessons go on a shared board and only take effect after a human signs off.
9. **Autonomy is earned and can be lost.** An agent's freedom in each area grows with its verified record and drops after an error.
10. **An agent's workspace is its own, never sealed.** No other process writes to it, and a human can always read it, pause it or stop it.

## What one night taught us

In a single session (Oct 29–30, 2026) agents, despite written rules:

- ran 26 parallel jobs on a laptop in use;
- left 24 orphaned processes running for hours;
- started a server on the port of a live service;
- leaked test data into a live roster;
- minted real license keys with a production signing key.

Rules 3, 7, 8 and 10 cover these only if they're enforced by the tool. So: hard per-agent CPU and process caps, teardown of everything an agent starts, fences around ports, data and devices, and no secrets unless granted. Details: [anthropics/claude-code#91081](https://github.com/anthropics/claude-code/issues/91081).

*Patent pending (U.S. provisionals 64/184,861 and 64/184,896). Shared to start a conversation. Use the ideas; credit appreciated.*
