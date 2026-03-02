Only after that do you deploy to a production VPS with hardened defaults.

Stage 1: Local-only testing (strongly recommended)

This is the safest and most controllable environment.

You run the app bound to 127.0.0.1 only. You trigger payloads manually in your own browser, using local HTML files or a simple test page. You confirm that callbacks are recorded, rate limiting works, screenshots are captured, and nothing crashes.

At this stage, you should not open ports on your router, not use port forwarding, and not use a public tunnel. Everything stays on your machine.

For screenshot testing, a local test page like a static HTML file opened in your browser is sufficient. You don’t need cross-origin behavior yet.

This stage validates:

Sanitization

Rate limiting

Screenshot capture

Disk usage

Error handling

Zero external risk.

Stage 2: Isolated public testing (controlled exposure)

Once local testing is solid, you need to test real-world conditions: public IPs, real browser origins, and network latency.

The safest way to do this is temporary, controlled exposure, not a permanent public service.

Two good options here are:

A short-lived VPS with a strict firewall

A tunneling service used only during testing

If you use a VPS, lock it down aggressively:

Firewall allows inbound traffic only from your home IP

No DNS records pointing to it

Random high port instead of 80/443

No public references to the URL

If you use a tunnel, treat it as disposable:

Only run it while testing

Rotate the URL afterward

Never reuse tokens

At this stage, you test:

Screenshot capture on real websites

Rate limiting under burst traffic

Behavior behind NAT/CDN

Disk growth over time

You still assume the service could be abused, so you minimize how long it’s reachable.

Stage 3: Production deployment (only when ready)

Only after the above should you deploy publicly.

At that point, you should already have:

Rate limiting enabled

Body size limits

Screenshot size limits

Disk retention policies

No dashboard

No authentication endpoints

No introspection routes

Production should assume:

Malicious traffic

Scanning

Garbage payloads

Intentional attempts to crash or fill disk

Your current design is already well-aligned with this assumption.

Should you test on your local network?

Testing on your local machine is good.
Testing on your local network (LAN) is fine but unnecessary unless you’re testing multiple devices.

I do not recommend:

Exposing this via router port forwarding

Running it on a home NAS with open ports

Testing from multiple machines on the same LAN as a substitute for public testing

Local ≠ public. The behaviors you care about (headers, IPs, CSP, cross-origin issues) show up once you go public, not on a LAN.

Additional safety recommendations (very important)

Even in testing, you should:

Use fake tokens only

Never reuse a token across environments

Never leave the service running unattended when public

Rotate or delete the database between stages

Keep screenshots in a separate directory you can wipe easily

And one subtle but important point:
Do not test payloads on sites you don’t own or have permission to test, even during development. It’s easy to accidentally cross legal lines with blind XSS tooling.
