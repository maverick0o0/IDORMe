# IDORMe Burp Suite Extension

IDORMe is a Burp Suite extension that assists penetration testers when
hunting for Insecure Direct Object Reference (IDOR) vulnerabilities.  It
provides a reproducible mutation engine, a queue based executor and a
set of heuristics to infer the likely owner of a request.

## Features

* **Burp Integration** – Registers a suite tab and context menu action to
  send requests to the extension.
* **Mutation Engine** – Applies deterministic rules to parameters so it
  is easy to reason about which payloads were generated.
* **Execution Queue** – Mutated requests can be replayed using a
  user-provided transport function.  For safety the default executor does
  not send network traffic.
* **Owner Inference** – Path, parameter and header heuristics are used to
  guess which account owns the request so testers can prioritise their
  analysis.

## Installation

1. Build the extension into a JAR using [Jython 2.7+](https://www.jython.org/).
2. Within Burp Suite navigate to **Extender → Extensions** and click
   **Add**.
3. Select **Extension type** `Python` and choose the generated JAR.
4. Once loaded, the `IDORMe` tab becomes available and the context menu
   entry "Send to IDORMe" appears when right-clicking HTTP traffic.

## Development

The project ships with a unit test suite that exercises the mutation
rules, mutation assembly, and owner inference heuristics.

```bash
python -m unittest discover -s tests -p "test_*.py"
```

The modules under `src/idor_me` are intentionally written so they can be
executed using CPython for testing while remaining compatible with the
Jython runtime used by Burp Suite.
