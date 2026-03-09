# debug_indirect

Diagnostic tool for AAP (Ansible Automation Platform) Indirect Managed Node Counting failures.

When indirect node counting isn't working — `main_eventquery` has loaded queries but `main_indirectmanagednodeaudit` remains empty — this tool connects to the controller API, fetches job event streams, and analyses the module return data to identify exactly why the jq queries are failing.

No `event_query.yml` file or database access needed. The script has built-in knowledge of what each collection's queries expect and checks the actual `event_data.res` against those expectations.

## Requirements

- Python 3.8+
- `requests` library (`pip3 install requests`)

## Usage

### Diagnose a specific job

```bash
python3 diagnose_indirect_nodes.py 40754 \
    --gateway https://gateway.example.com \
    -u admin -p 'password' \
    --no-verify-ssl
```

### Auto-discover and diagnose recent jobs

Finds one example of each unique job template from the last day that used relevant collection modules:

```bash
python3 diagnose_indirect_nodes.py --discover \
    --gateway https://gateway.example.com \
    -u admin -p 'password' \
    --no-verify-ssl
```

### Look back further or analyse more jobs

```bash
python3 diagnose_indirect_nodes.py --discover --days 7 --limit 10 \
    --gateway https://gateway.example.com \
    -u admin -p 'password' \
    --no-verify-ssl
```

### Direct controller access (AAP < 2.5)

```bash
python3 diagnose_indirect_nodes.py --discover \
    --controller https://controller.example.com \
    --token <oauth_token> \
    --no-verify-ssl
```

### Save results to file

```bash
python3 diagnose_indirect_nodes.py --discover \
    --gateway https://gateway.example.com \
    -u admin -p 'password' \
    --no-verify-ssl \
    --output diagnostic_report.json
```

## Environment variables

Instead of passing credentials every time, you can set:

| Variable | Description |
|---|---|
| `GATEWAY_HOST` | AAP 2.5 gateway URL |
| `CONTROLLER_HOST` | Direct controller URL |
| `CONTROLLER_TOKEN` | OAuth2 bearer token |
| `CONTROLLER_USERNAME` | Username |
| `CONTROLLER_PASSWORD` | Password |
| `CONTROLLER_VERIFY_SSL` | Set to `false` to skip TLS verification |

## How it works

1. **Authenticates** to the AAP controller via the gateway (session + CSRF tokens) or directly (token/basic auth)
2. **Discovers jobs** that ran modules from collections with `event_query.yml` files (VMware, Azure, AWS, MCP)
3. **Fetches event streams** for those jobs, filtering to `runner_on_ok` events only (the only event type AAP processes for indirect node counting)
4. **Analyses `event_data.res`** against what the collection's jq queries expect to find — checking root keys, container types, and identifier fields
5. **Reports mismatches** showing exactly which key the query expects vs what the module actually returned

## What the output means

- **`[OK]`** — The module return data matches what the query expects. Nodes would be extracted successfully.
- **`[FAIL] MISSING_ROOT_KEY`** — The query looks for a key (e.g. `.state`, `.guests`) that doesn't exist in the module's return data. This usually means the collection's `event_query.yml` was generated for a different version than what's installed.
- **`[FAIL] NULL_ROOT_KEY`** — The key exists but is null. The `select(. != null)` filter in the query skips it.
- **`[FAIL] EMPTY_CONTAINER`** — The key exists and is a list, but it's empty. No items to iterate.
- **`[FAIL] MISSING_ID_FIELD`** — The data structure is correct but none of the expected identifier fields (moid, instance_uuid, id, etc.) are present.
- **`[FAIL] NO_RES`** — `event_data.res` is missing on a `runner_on_ok` event, which shouldn't normally happen.

## Supported collections

The tool has built-in expectations for modules from:

- `vmware.vmware` (guest_info, vm_powerstate, appliance_info, cluster_info, etc.)
- `community.vmware` (vmware_guest, vmware_vm_info, vcenter_domain_user_group_info, etc.)
- `azure.azcollection` (azure_rm_resourcegroup, azure_rm_virtualnetwork, azure_rm_subnet, etc.)
- `amazon.aws` (ec2_instance, ec2_instance_info)
- `ansible.mcp` (run_tool)

Modules not in the built-in map are analysed heuristically by scanning the return data for identifiable fields.

## Related

- [query-file-generator](https://github.com/jonnyfiveiq/query-file-generator) — Ansible collection that generates the `event_query.yml` files used by indirect node counting
