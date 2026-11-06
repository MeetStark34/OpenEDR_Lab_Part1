VIRTUAL SOC LAB
SIMULATED EVIDENCE – NOT CAPTURED FROM A LIVE SYSTEM

HOW TO OPEN
Double-click index.html. It opens in your normal browser and runs entirely
from this folder. No Docker, VM, Elasticsearch, server, install, download or
internet connection is needed. Keep the css, js and screenshots folders next
to index.html.

WHAT IS IN THE APP
SOC Overview     Live tiles, charts, rule firings and ATT&CK coverage. Everything
                 clicks through to the detail behind it.
Discover         KQL search with autocomplete, syntax errors, histogram drag-to-zoom,
                 field statistics, filters, sorting, columns, document view (Table
                 and JSON), saved searches, and CSV or NDJSON export.
Alerts           Alert queue with filters, bulk actions, status, assignee,
                 classification, notes, and "Check my triage".
Detection Rules  10 rules (query, threshold, sequence). Enable, edit, preview live,
                 revert, or write your own KQL rule. Alerts recalculate instantly.
Process Trees    Expandable trees with alert badges, search, lineage, and network
                 and file activity per process.
Event Timeline   Swimlanes with scroll-zoom, drag-to-select, alert markers and
                 Follow PID.
Scenarios        R1, R2, S1, S2 and S3 as guided demonstrations with event replay,
                 live threshold meters and investigation steps. S3 includes a paste
                 tester that compares text with the query. Nothing is executed.
Field Reference  Which field names are documented, seen, found in source or assumed.

SUGGESTED FIRST INVESTIGATION
1. Open Alerts and pick the high-severity S1 alert.
2. Use Process tree, then Open in Discover, then Timeline from the alert.
3. Classify it, add a note, and repeat for the other alerts.
4. Press Check my triage, then turn on Lab answers to compare.

CONTROLS
Lab answers   Off by default so triage is a real exercise. On shows ground-truth
              labels and the event IDs used in the report.
Reset lab     Clears rule edits, triage and saved searches.
/ key         Focuses the KQL box in Discover.
Esc           Closes the side panel.
Your edits are kept in this browser only, using local storage.

WHAT THIS IS NOT
- This is a teaching simulation of a Kibana-style workflow. It is not Kibana, it
  is not affiliated with Elastic or OpenEDR, and it connects to nothing.
- All 91 events are synthetic and come from the report's dataset. They are not
  captured telemetry.
- Most field names are assumed. See Field Reference.
- The KQL engine models case-sensitive keyword and wildcard matching. A query that
  works here must still be tested in a real Kibana.
- Threshold rules here use a true sliding window. Real scheduled rules can behave
  differently around run boundaries.
- The screenshots show this simulator. They are not real lab evidence and do not
  meet an assignment requirement for real Kibana screenshots.

FILES
index.html            The app
css, js               App code. js/data.js holds the synthetic events and rules.
screenshots           14 PNG captures of the running app
TEST_RESULTS_EDGE.txt, TEST_RESULTS_CHROME.txt   Automated browser test results
