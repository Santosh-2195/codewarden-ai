# Detection Rule Catalog

Generated with `python -m codewarden rules --markdown`. Rules are generic (framework/language patterns); they produce *candidates* that the AI layer verifies, rejects, re-scores and explains. Nothing in this list is specific to the CDF TaskFlow sample.

| Rule ID | Title | CWE | Default severity | Languages |
|---|---|---|---|---|
| `CW-SECRET-001` | Hard-coded secret in source | CWE-798 | High | * |
| `CW-JS-XSS-001` | Cross-site scripting via dangerouslySetInnerHTML | CWE-79 | High | typescript, javascript |
| `CW-JS-XSS-002` | Untrusted data written to an HTML sink | CWE-79 | High | typescript, javascript, html |
| `CW-JS-SQLI-001` | SQL injection via string-built query | CWE-89 | High | typescript, javascript |
| `CW-JS-CMDI-001` | OS command built from dynamic input | CWE-78 | High | typescript, javascript |
| `CW-JS-EVAL-001` | Dynamic code execution (eval / new Function) | CWE-95 | High | typescript, javascript, html |
| `CW-JS-PATH-001` | File path built from request input | CWE-22 | High | typescript, javascript |
| `CW-JS-REDIRECT-001` | Open redirect using request input | CWE-601 | Medium | typescript, javascript, html |
| `CW-JS-AUTHZ-001` | Privileged data access without authenticating the caller | CWE-862 | High | typescript, javascript |
| `CW-JS-MASS-001` | Mass assignment: request body written to the database unfiltered | CWE-915 | High | typescript, javascript |
| `CW-JS-CORS-001` | Permissive CORS policy (Access-Control-Allow-Origin: *) | CWE-942 | Low | * |
| `CW-JS-ERRLEAK-001` | Internal error details returned to the client | CWE-209 | Low | typescript, javascript |
| `CW-JS-RAND-001` | Insecure randomness for security-sensitive value | CWE-338 | Medium | typescript, javascript, html |
| `CW-JS-HASH-001` | Weak hash used for password or secret | CWE-328 | Medium | typescript, javascript, html |
| `CW-JS-TLS-001` | TLS certificate validation disabled | CWE-295 | High | * |
| `CW-JS-JWT-001` | JWT accepted without proper verification | CWE-347 | High | typescript, javascript |
| `CW-JS-STORAGE-001` | Authentication token stored in localStorage | CWE-922 | Low | typescript, javascript, html |
| `CW-JS-MSG-001` | postMessage sent to any origin | CWE-345 | Low | typescript, javascript, html |
| `CW-CFG-DEBUG-001` | Debug / verbose mode enabled in committed configuration | CWE-489 | Low | typescript, javascript, json, yaml, toml |
| `CW-PY-SQLI-001` | SQL injection via formatted query string | CWE-89 | High | python |
| `CW-PY-EXEC-001` | Dynamic code execution (eval/exec) | CWE-95 | High | python |
| `CW-PY-CMDI-001` | OS command injection risk | CWE-78 | High | python |
| `CW-PY-DESER-001` | Insecure deserialisation (pickle/marshal) | CWE-502 | High | python |
| `CW-PY-YAML-001` | Unsafe YAML loading | CWE-502 | Medium | python |
| `CW-PY-TLS-001` | TLS verification disabled in HTTP client | CWE-295 | Medium | python |
| `CW-PY-DEBUG-001` | Framework debug mode enabled | CWE-489 | Medium | python |
| `CW-PY-HASH-001` | Weak hash used for password or secret | CWE-328 | Medium | python |
| `CW-PY-SSTI-001` | Server-side template injection | CWE-1336 | High | python |
| `CW-PY-JWT-001` | JWT signature verification disabled | CWE-347 | High | python |
| `CW-SQL-RLS-001` | Over-permissive RLS read policy (USING true) | CWE-284 | Medium | sql |
| `CW-SQL-RLS-002` | Over-permissive RLS write policy | CWE-284 | High | sql |
| `CW-SQL-RLS-003` | RLS policy subquery does not scope rows to the current user | CWE-863 | Medium | sql |
| `CW-SQL-RLS-004` | Privilege escalation through self-service row update | CWE-269 | High | sql |
| `CW-SQL-RLS-005` | RLS write policy does not verify access to the parent record | CWE-639 | Medium | sql |
| `CW-SQL-RLS-006` | Row Level Security not enabled on table | CWE-284 | High | sql |
| `CW-SQL-GRANT-001` | Write privileges granted to anonymous/public role | CWE-732 | High | sql |
| `CW-SQL-FUNC-001` | SECURITY DEFINER function without fixed search_path | CWE-427 | Medium | sql |
| `CW-SQL-DYN-001` | Dynamic SQL built by concatenation in database function | CWE-89 | High | sql |
