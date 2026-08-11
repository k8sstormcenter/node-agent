# Benchmark signing material — published, compromised by design

These private keys are committed so the benchmark can sign its fixtures on a
clean runner; a signature made by them authenticates nothing.

`trust-policy.signed.json` is signed with the published demo root key, whose
public half is compiled into the demo node-agent image.

The benchmark uses them to measure the cost of signature verification with the
feature ON; nothing here is fit for any other purpose.
