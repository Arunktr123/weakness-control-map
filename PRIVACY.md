# Privacy

Weakness → Control Map does not collect, store or transmit any data.

- The skill runs `skills/weakness-control-map/scripts/lookup.py` on your machine (or in the agent's own sandbox) with
  the CWE, CAPEC, control or SSDF ids, or the search words, taken from your request.
- The script reads only the JSON files bundled with the plugin. It makes no network connections, writes no files and
  keeps no logs or history.
- The plugin has no hooks, MCP servers, telemetry or background processes, and it does not change any settings or
  permissions.

What you type and what the agent does with the results stay within your agent application and are governed by that
application's own privacy terms.

Questions: open an issue at https://github.com/Arunktr123/weakness-control-map/issues
