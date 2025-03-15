# httpc_tasks

Query redhat database for status of a list of CVEs in the file cvelist.txt.
This will provide the severity and score for each CVE along with the current
state of the fix for the CVE in any package with the vulnerability
that is part of the RHEL 8 codebase.

## Development

```sh
gleam run   # Run the project
gleam test  # Run the tests
```
