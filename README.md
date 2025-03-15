# httpc_tasks

Query redhat database for status of a list of CVEs in the file cvelist.txt.
This will provide the severity and score for each CVE along with the current
state of the fix for the CVE in any package with the vulnerability
that is part of the RHEL 8 codebase.

This largely was a testbed so I could develop a feel for asynchronous tasks
in gleam, and work out a function which could run a subset of the tasks
asynchronously so no more than N would be running at one time. In this case
I do simultaneous calls to the Red Hat API, but limit it to 10 at a time.

## Development

```sh
gleam run   # Run the project
gleam test  # Run the tests
```
