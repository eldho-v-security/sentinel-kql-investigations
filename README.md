# Microsoft Sentinel & KQL Investigations

Practical security investigation examples covering identity activity,
log analysis, and threat detection.

**Author:** Eldho Varghese  
**Status:** Portfolio in development  
**Data:** Synthetic examples; no employer or customer data.

## Investigation 01: Failed Sign-ins Followed by Success

### Objective

Identify an account with at least three unsuccessful sign-in events
from the same IP address during the 10 minutes preceding a successful
sign-in.

This pattern warrants investigation but does not prove compromise.
A legitimate user correcting a mistyped password can produce it.

### Sample Scenario

The fictional account analyst@example.com has three unsuccessful
sign-ins between 09:00 and 09:04 UTC, followed by a successful sign-in
at 09:05 UTC from the same IP address.

The threshold of three is for this demonstration, not a production
recommendation.

### Run the Demonstration

Run the complete query below in an Azure Monitor Logs environment
that supports KQL. The datatable supplies its own sample records;
it does not require an existing SigninLogs table.

```kusto
let Events = datatable(
    EventTime:datetime,
    UserPrincipalName:string,
    IPAddress:string,
    ResultType:string
)
[
    datetime(2026-11-01T09:00:00Z), "analyst@example.com", "192.0.2.10", "50126",
    datetime(2026-11-01T09:02:00Z), "analyst@example.com", "192.0.2.10", "50126",
    datetime(2026-11-01T09:04:00Z), "analyst@example.com", "192.0.2.10", "50126",
    datetime(2026-11-01T09:05:00Z), "analyst@example.com", "192.0.2.10", "0",
    datetime(2026-11-01T09:06:00Z), "user2@example.com", "192.0.2.20", "0"
];
let Unsuccessful = Events
| where ResultType != "0"
| project FailureTime = EventTime, UserPrincipalName, IPAddress;
let Successful = Events
| where ResultType == "0"
| project SuccessTime = EventTime, UserPrincipalName, IPAddress;
Successful
| join kind=inner (Unsuccessful) on UserPrincipalName, IPAddress
| where FailureTime >= SuccessTime - 10m
    and FailureTime < SuccessTime
| summarize
    UnsuccessfulEvents = count(),
    FirstFailure = min(FailureTime),
    LastFailure = max(FailureTime)
    by UserPrincipalName, IPAddress, SuccessTime
| where UnsuccessfulEvents >= 3
| project UserPrincipalName, IPAddress, UnsuccessfulEvents,
          FirstFailure, LastFailure, SuccessTime
```

### Expected Result — Not a Captured Execution Result

| Account | IP address | Unsuccessful events | Successful sign-in |
|---|---|---|---|
| analyst@example.com | 192.0.2.10 | 3 | 2026-11-01 09:05 UTC |

The second account should not appear because it has no preceding
unsuccessful sign-ins in the sample.

### Investigation Workflow

1. Review the original events and their result descriptions.
2. Compare the IP, device, application, and location with the user's
   usual activity.
3. Review authentication details, MFA results, and Conditional Access.
4. Check whether the IP attempted to access other accounts.
5. Review activity after the successful sign-in, including relevant
   audit events and endpoint alerts.
6. Validate the activity with the user through an approved channel.
7. Document the evidence, scope, conclusion, and response.

### Response Decision

- **Confirmed legitimate:** Record the explanation and close with
  supporting evidence.
- **Suspicious but unresolved:** Escalate for further investigation.
- **Confirmed compromise:** Follow the approved incident response
  process, including session revocation, credential remediation,
  and review of affected resources as appropriate.

### Limitations

- Nonzero result codes can represent different unsuccessful or
  interrupted authentication outcomes; they are not all bad passwords.
- Matching the same IP can miss an attacker who changes IP addresses.
- Shared VPN or proxy addresses can complicate attribution.
- This example counts records, not verified unique authentication attempts.
- It does not detect password spraying across multiple accounts.
- Production use requires tuning, deduplication, ingestion-delay
  handling, and testing against representative data.
- This is a learning query, not a production-ready analytics rule.

### Validation Status

The expected output is derived from the sample data.
Execution in Microsoft Sentinel has not yet been documented.

Suggested checks:
- Run the sample unchanged: expect one result.
- Remove one unsuccessful event: expect no results.
- Move the success beyond the 10-minute window: expect no results.
- Change the success IP: expect no results.

### References

- [Microsoft SigninLogs table reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs)
- [KQL time-window joins](https://learn.microsoft.com/en-us/kusto/query/join-time-window)
