SIMULATED EVIDENCE – NOT CAPTURED FROM A LIVE SYSTEM

synthetic_events.ndjson  the 91 fictional events behind the report
lab_data.py              dataset, KQL queries and hand-written expected hits
validate.py              KQL-subset evaluator; run: python validate.py
mutation_test.py         proves the validator can fail; run: python mutation_test.py

These scripts check the report's internal consistency. They do not emulate Kibana.
