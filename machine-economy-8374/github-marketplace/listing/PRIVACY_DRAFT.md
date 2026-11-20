# Privacy text preparation — owner completion required

The proposed integration handles GitHub installation/account/repository IDs,
delivery IDs and payload digests, plan-change notifications, owner-bound public
service origins, commit SHAs and public receipt references. The Action processes
the selected local suite files and writes a local result JSON; optional checker
execution has the chosen runner's permissions.

Before publication, the operator must state the actual data controller/contact,
host/custody boundary, data recipients, retention periods, deletion procedure,
billing-record obligations and incident contact. These facts are not established
by the source candidate and are not invented here. No zero-retention or
confidentiality promise follows from source code or this draft.

The host integration must account for GitHub's published cancelled-trial private
data deletion expectation (within30days of cancellation); this candidate has no
bound production data store or deletion execution and cannot certify compliance.

Secret material stays in existing TVC/SKAP-authorized custody. Public receipt
links may expose public evidence; private repository contents must not be sent
to the public router by default. The current registration adapter sends only
the explicitly owner-bound service origin, never repository files.
