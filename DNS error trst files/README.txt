DNS ERROR TEST FILES

1. dns_response_errors.csv
   Correct CSV structure. Contains DNS response codes such as NXDOMAIN, SERVFAIL,
   REFUSED, FORMERR and TIMEOUT, plus a few successful responses. Upload this to
   test DNS response-error analysis.

2. invalid_missing_response_column.csv
   Intentionally missing the required 'response' column. Upload this to test the
   website's missing-column validation message.

3. invalid_domain_and_values.csv
   Has the required headers but includes invalid/empty domain values and a bad
   timestamp. Upload this to test invalid-record handling. The current simple
   browser detector validates domain format; it does not fully validate timestamps
   or query-type semantics.

These are synthetic educational test records, not captured real network traffic.
