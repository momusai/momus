# Security

## Reporting a vulnerability in Momus

If you find a security issue in Momus itself (the scanner, the judge, the report
generators — not in some model you scanned with it), please don't open a public
issue. Email the maintainers or use GitHub's private "Report a vulnerability"
button on the Security tab.

Include what you'd expect: what the bug is, how to reproduce it, and what an
attacker could do with it. We'll acknowledge within a few days and keep you in
the loop until it's fixed. Once there's a fix we're happy to credit you.

There's no bounty program — this is a volunteer OSS project.

## Using Momus responsibly

Momus sends adversarial prompts to whatever endpoint you point it at. Only scan
systems you own or have explicit permission to test. Running it against someone
else's API can violate their terms of service or the law. That's on you.

The attack payloads in `packs/` are intentionally adversarial (jailbreaks,
injection, exfiltration attempts). They're here so you can test your own
defenses. Don't use them against systems you're not authorized to test.

## A note on the judge

The `llm_judge` scorer sends the target's responses to a second model for
grading. If you're scanning something whose responses may contain sensitive
data, be aware that data leaves your machine when a hosted judge is configured.
Use a local judge (Ollama, vLLM) if that matters to you — see the README.
