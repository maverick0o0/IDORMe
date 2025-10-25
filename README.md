# IDORMe

IDORMe is a Burp Suite extension (written in Python for Jython) that automates a concrete checklist for bypassing Insecure Direct Object Reference (IDOR) protections. It consumes a captured request, generates a large catalogue of mutations based on the mutation matrix described in the project brief, sends each request, and surfaces the responses in an interactive table so analysts can quickly inspect promising bypass attempts.

## Features

- **Single-click generation** – highlight a request in Burp and choose **Send to IDORMe**. The extension parses the request, applies the mutation rules, and issues the crafted traffic automatically.
- **Comprehensive rule coverage** – implements the global rules (method flipping, HTTP verb tunnelling, mixed casing, suffix probing, content-type re-encoding, and parameter injection) plus the base-specific rules for identifiers located in the path, body, or query string.
- **Response telemetry** – each mutation shows the originating rule, HTTP status, response length, and an owner hint when the response body contains the attacker or victim identifier. Selecting a row displays the exact request/response pair for deeper inspection.
- **Owner inference helpers** – IDORMe highlights when responses contain the victim identifier, making it easier to spot successful scope expansion.

## Installation

1. Build a Jython standalone JAR (2.7.x) and configure Burp Suite to use it under **Extender → Options**.
2. Copy the `src/idorme` directory to a location accessible by Burp or package it as a JAR using the Jython tools.
3. In Burp Suite, open **Extender → Extensions**, choose **Add**, select **Python** as the extension type, and point to the `src/idorme/__init__.py` file (or a bundled script that imports `BurpExtender`).

## Usage

1. Capture or repeat the target request inside Burp (Proxy history or Repeater).
2. Right-click the request and select **Send to IDORMe**.
3. (Optional) Provide a parameter name and attacker/victim identifiers in the IDORMe tab. Empty fields will be populated with random numeric identifiers.
4. Click **Generate & Send** to execute all mutation rules. The results table will populate with response metadata, and you can inspect individual requests by selecting any row.

## Development

- The project targets Python 2.7 (Jython) compatibility. Avoid Python 3-only syntax such as f-strings.
- Run `python -m compileall src` to ensure the sources compile cleanly.
- Contributions should focus on expanding the mutation rules, improving heuristics, or enhancing the UI/owner inference logic.

## License

This project is distributed under the MIT License. See `LICENSE` for details.
