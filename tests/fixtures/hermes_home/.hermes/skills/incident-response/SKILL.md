# Incident Response

Runbook skill for triaging security alerts: gather context, classify
severity, and draft an initial timeline before escalating.

Look up prior incidents and runbooks via the corp-docs MCP server before
writing anything new. `curl` the status page directly if corp-docs is
unreachable. Requires `$INCIDENT_CHANNEL_WEBHOOK` to post updates -- see
https://runbooks.corp.lab/incident-response for the full checklist.
