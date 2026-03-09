#!/usr/bin/env python3
"""
diagnose_indirect_nodes.py
==========================
Single-tool diagnostic for AAP Indirect Managed Node Counting failures.

Connects to the AAP controller (via gateway or direct), finds jobs that
used modules from collections with event_query.yml files, fetches their
event streams, and analyses the event_data.res to identify exactly why
jq queries would fail to extract node identifiers.

No event_query.yml file needed — the script knows what the queries expect
based on the collection module FQCN and inspects the actual return data
to pinpoint mismatches.

Usage:
    # Diagnose a specific job:
    python3 diagnose_indirect_nodes.py 40754 \
        --gateway https://gateway.example.com \
        -u admin -p 'secret' --no-verify-ssl

    # Auto-discover and diagnose recent jobs (last 7 days):
    python3 diagnose_indirect_nodes.py --discover \
        --gateway https://gateway.example.com \
        -u admin -p 'secret' --no-verify-ssl

    # Discover from last 14 days, limit to 10 jobs:
    python3 diagnose_indirect_nodes.py --discover --days 14 --limit 10 \
        --gateway https://gateway.example.com \
        -u admin -p 'secret' --no-verify-ssl

    # Save full diagnostic output to file:
    python3 diagnose_indirect_nodes.py --discover \
        --gateway https://gateway.example.com \
        -u admin -p 'secret' --no-verify-ssl \
        --output diagnostic_report.json

Environment variables:
    GATEWAY_HOST, CONTROLLER_HOST, CONTROLLER_TOKEN,
    CONTROLLER_USERNAME, CONTROLLER_PASSWORD, CONTROLLER_VERIFY_SSL
"""

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    sys.exit("ERROR: 'requests' is required.  pip3 install requests")


# ============================================================================
# Known collection query expectations
# ============================================================================
# This maps FQCN prefixes to what the event_query.yml queries typically
# expect to find in event_data.res. Built from the query-file-generator
# patterns and common collection query files.
#
# Format:
#   "fqcn": {
#       "root_key": the top-level key in res the query accesses (e.g. ".vm"),
#       "container": "list" or "dict" — whether query uses []  or select(),
#       "id_fields": ordered list of identifier fields the query looks for,
#       "description": human-readable explanation,
#   }
#
# For modules not explicitly listed, we fall back to heuristic analysis.

QUERY_EXPECTATIONS = {
    # ── VMware (vmware.vmware collection) ──
    "vmware.vmware.guest_info": {
        "root_key": "guests",
        "container": "list",
        "id_fields": ["moid", "instance_uuid"],
        "facts_fields": {"infra_type": "PrivateCloud", "device_type": "VM"},
        "description": "Expects .guests[] array with moid and instance_uuid per guest",
    },
    "vmware.vmware.vm_powerstate": {
        "root_key": "vm",
        "container": "dict",
        "id_fields": ["moid", "instance_uuid"],
        "facts_fields": {"infra_type": "PrivateCloud", "device_type": "VM"},
        "description": "Expects .vm dict with moid",
    },
    "vmware.vmware.appliance_info": {
        "root_key": "appliance",
        "container": "dict",
        "id_fields": ["id"],
        "facts_fields": {"infra_type": "PrivateCloud"},
        "description": "Expects .appliance dict with id",
    },
    "vmware.vmware.cluster_info": {
        "root_key": "clusters",
        "container": "list",
        "id_fields": ["moid", "name"],
        "facts_fields": {"infra_type": "PrivateCloud", "device_type": "Cluster"},
        "description": "Expects .clusters[] array",
    },
    "vmware.vmware.datacenter_info": {
        "root_key": "datacenters",
        "container": "list",
        "id_fields": ["moid", "name"],
        "facts_fields": {"infra_type": "PrivateCloud", "device_type": "Datacenter"},
        "description": "Expects .datacenters[] array",
    },
    "vmware.vmware.host_info": {
        "root_key": "hosts",
        "container": "list",
        "id_fields": ["moid", "name"],
        "facts_fields": {"infra_type": "PrivateCloud", "device_type": "Host"},
        "description": "Expects .hosts[] array",
    },

    # ── VMware (community.vmware collection) ──
    "community.vmware.vmware_guest": {
        "root_key": "instance",
        "container": "dict",
        "id_fields": ["moid", "instance_uuid", "hw_product_uuid"],
        "facts_fields": {"infra_type": "PrivateCloud", "device_type": "VM"},
        "description": "Expects .instance dict with moid or instance_uuid",
    },
    "community.vmware.vmware_guest_info": {
        "root_key": "instance",
        "container": "dict",
        "id_fields": ["moid", "instance_uuid", "hw_product_uuid"],
        "facts_fields": {"infra_type": "PrivateCloud", "device_type": "VM"},
        "description": "Expects .instance dict with moid or instance_uuid",
    },
    "community.vmware.vmware_vm_info": {
        "root_key": "virtual_machines",
        "container": "list",
        "id_fields": ["moid", "uuid"],
        "facts_fields": {"infra_type": "PrivateCloud", "device_type": "VM"},
        "description": "Expects .virtual_machines[] array",
    },
    "community.vmware.vcenter_domain_user_group_info": {
        "root_key": "domain_user_groups",
        "container": "list",
        "id_fields": ["id"],
        "facts_fields": {"infra_type": "PrivateCloud"},
        "description": "Expects .domain_user_groups[] array",
    },

    # ── Azure (azure.azcollection) ──
    "azure.azcollection.azure_rm_resourcegroup": {
        "root_key": "state",
        "container": "dict",
        "id_fields": ["id", "name"],
        "facts_fields": {"infra_type": "PublicCloud", "device_type": "ResourceGroup"},
        "description": "Expects .state dict with id",
    },
    "azure.azcollection.azure_rm_resourcegroup_info": {
        "root_key": "resourcegroups",
        "container": "list",
        "id_fields": ["id", "name"],
        "facts_fields": {"infra_type": "PublicCloud", "device_type": "ResourceGroup"},
        "description": "Expects .resourcegroups[] array with id",
    },
    "azure.azcollection.azure_rm_virtualnetwork": {
        "root_key": "state",
        "container": "dict",
        "id_fields": ["id", "name"],
        "facts_fields": {"infra_type": "PublicCloud", "device_type": "VirtualNetwork"},
        "description": "Expects .state dict with id",
    },
    "azure.azcollection.azure_rm_virtualnetwork_info": {
        "root_key": "virtualnetworks",
        "container": "list",
        "id_fields": ["id", "name"],
        "facts_fields": {"infra_type": "PublicCloud", "device_type": "VirtualNetwork"},
        "description": "Expects .virtualnetworks[] array with id",
    },
    "azure.azcollection.azure_rm_securitygroup": {
        "root_key": "state",
        "container": "dict",
        "id_fields": ["id", "name"],
        "facts_fields": {"infra_type": "PublicCloud", "device_type": "SecurityGroup"},
        "description": "Expects .state dict with id",
    },
    "azure.azcollection.azure_rm_securitygroup_info": {
        "root_key": "securitygroups",
        "container": "list",
        "id_fields": ["id", "name"],
        "facts_fields": {"infra_type": "PublicCloud", "device_type": "SecurityGroup"},
        "description": "Expects .securitygroups[] array with id",
    },
    "azure.azcollection.azure_rm_subnet": {
        "root_key": "state",
        "container": "dict",
        "id_fields": ["id", "name"],
        "facts_fields": {"infra_type": "PublicCloud", "device_type": "Subnet"},
        "description": "Expects .state dict with id",
    },
    "azure.azcollection.azure_rm_subnet_info": {
        "root_key": "subnets",
        "container": "list",
        "id_fields": ["id", "name"],
        "facts_fields": {"infra_type": "PublicCloud", "device_type": "Subnet"},
        "description": "Expects .subnets[] array with id",
    },
    "azure.azcollection.azure_rm_subscription_info": {
        "root_key": "subscriptions",
        "container": "list",
        "id_fields": ["id", "subscription_id"],
        "facts_fields": {"infra_type": "PublicCloud", "device_type": "Subscription"},
        "description": "Expects .subscriptions[] array with id",
    },
    "azure.azcollection.azure_rm_availabilityset": {
        "root_key": "state",
        "container": "dict",
        "id_fields": ["id", "name"],
        "facts_fields": {"infra_type": "PublicCloud", "device_type": "AvailabilitySet"},
        "description": "Expects .state dict with id",
    },
    "azure.azcollection.azure_rm_availabilityset_info": {
        "root_key": "ansible_info",
        "container": "dict",
        "id_fields": ["id", "name"],
        "facts_fields": {"infra_type": "PublicCloud", "device_type": "AvailabilitySet"},
        "description": "Expects .ansible_info dict (may contain azure_availabilitysets)",
    },
    "azure.azcollection.azure_rm_applicationsecuritygroup": {
        "root_key": "state",
        "container": "dict",
        "id_fields": ["id", "name"],
        "facts_fields": {"infra_type": "PublicCloud", "device_type": "AppSecurityGroup"},
        "description": "Expects .state dict with id",
    },
    "azure.azcollection.azure_rm_applicationsecuritygroup_info": {
        "root_key": "application_security_groups",
        "container": "list",
        "id_fields": ["id", "name"],
        "facts_fields": {"infra_type": "PublicCloud", "device_type": "AppSecurityGroup"},
        "description": "Expects .application_security_groups[] array with id",
    },
    "azure.azcollection.azure_rm_route": {
        "root_key": "state",
        "container": "dict",
        "id_fields": ["id", "name"],
        "facts_fields": {"infra_type": "PublicCloud", "device_type": "Route"},
        "description": "Expects .state dict with id",
    },
    "azure.azcollection.azure_rm_routetable": {
        "root_key": "state",
        "container": "dict",
        "id_fields": ["id", "name"],
        "facts_fields": {"infra_type": "PublicCloud", "device_type": "RouteTable"},
        "description": "Expects .state dict with id",
    },
    "azure.azcollection.azure_rm_routetable_info": {
        "root_key": "route_tables",
        "container": "list",
        "id_fields": ["id", "name"],
        "facts_fields": {"infra_type": "PublicCloud", "device_type": "RouteTable"},
        "description": "Expects .route_tables[] array with id",
    },
    "azure.azcollection.azure_rm_proximityplacementgroup": {
        "root_key": "state",
        "container": "dict",
        "id_fields": ["id", "name"],
        "facts_fields": {"infra_type": "PublicCloud", "device_type": "ProximityPlacementGroup"},
        "description": "Expects .state dict with id",
    },
    "azure.azcollection.azure_rm_proximityplacementgroup_info": {
        "root_key": "proximity_placement_groups",
        "container": "list",
        "id_fields": ["id", "name"],
        "facts_fields": {"infra_type": "PublicCloud", "device_type": "ProximityPlacementGroup"},
        "description": "Expects .proximity_placement_groups[] array with id",
    },

    # ── AWS (amazon.aws) ──
    "amazon.aws.ec2_instance": {
        "root_key": "instances",
        "container": "list",
        "id_fields": ["instance_id", "arn"],
        "facts_fields": {"infra_type": "PublicCloud", "device_type": "EC2"},
        "description": "Expects .instances[] array with instance_id",
    },
    "amazon.aws.ec2_instance_info": {
        "root_key": "instances",
        "container": "list",
        "id_fields": ["instance_id", "arn"],
        "facts_fields": {"infra_type": "PublicCloud", "device_type": "EC2"},
        "description": "Expects .instances[] array with instance_id",
    },

    # ── MCP (ansible.mcp) ──
    "ansible.mcp.run_tool": {
        "root_key": None,
        "container": "dict",
        "id_fields": ["tool_name", "mcp_server"],
        "facts_fields": {},
        "description": "Expects top-level .tool_name and .mcp_server",
    },
}

# Collection namespace prefixes to scan for
KNOWN_NAMESPACES = [
    "vmware.vmware.",
    "community.vmware.",
    "amazon.aws.",
    "azure.azcollection.",
    "ansible.mcp.",
]

# Priority order for identifier field detection (from query-file-generator)
ID_FIELD_PRIORITY = [
    "moid", "instance_uuid", "hw_product_uuid", "bios_uuid",
    "uuid", "arn", "resource_id", "instance_id",
    "id", "serial", "name",
]

# AAP only runs jq queries against these event types.
# runner_on_start has no res (module hasn't executed yet).
# runner_on_failed, runner_on_skipped etc. are not processed for INC.
PROCESSABLE_EVENT_TYPES = {"runner_on_ok"}


# ============================================================================
# URL helper
# ============================================================================

def ensure_absolute_url(url, base_url):
    if url is None:
        return None
    if not urlparse(url).scheme:
        return f"{base_url.rstrip('/')}{url}"
    return url


# ============================================================================
# Authentication (supports AAP 2.5 gateway + direct)
# ============================================================================

def authenticate_via_gateway(gateway_url, username, password, verify_ssl=True):
    base = gateway_url.rstrip("/")
    session = requests.Session()
    session.verify = verify_ssl

    for login_path in ["/api/gateway/v1/login/", "/api/login/"]:
        login_url = f"{base}{login_path}"
        try:
            print(f"  Trying {login_path} ...")
            session.get(login_url)
            csrf = session.cookies.get("csrftoken", "")

            headers = {"Content-Type": "application/json"}
            if csrf:
                headers["X-CSRFToken"] = csrf
                headers["Referer"] = login_url

            resp = session.post(login_url, json={"username": username, "password": password}, headers=headers)
            if resp.status_code in (200, 204, 302):
                if session.get(f"{base}/api/controller/v2/me/").status_code == 200:
                    print(f"  Authenticated (JSON + CSRF).")
                    return session, base

            s2 = requests.Session()
            s2.verify = verify_ssl
            s2.get(login_url)
            csrf2 = s2.cookies.get("csrftoken", "")
            if csrf2:
                r2 = s2.post(login_url, data={"username": username, "password": password},
                             headers={"X-CSRFToken": csrf2, "Referer": login_url,
                                      "Content-Type": "application/x-www-form-urlencoded"},
                             allow_redirects=False)
                if r2.status_code in (200, 204, 302):
                    if s2.get(f"{base}/api/controller/v2/me/").status_code == 200:
                        print(f"  Authenticated (form + CSRF).")
                        return s2, base
        except requests.exceptions.ConnectionError:
            continue

    for path in ["/api/gateway/v1/tokens/", "/api/controller/v2/tokens/"]:
        try:
            s = requests.Session(); s.verify = verify_ssl
            r = s.post(f"{base}{path}", json={"description": "diag temp", "scope": "read"},
                       auth=(username, password))
            if r.status_code in (200, 201):
                tok = r.json().get("token", "")
                if tok:
                    s.headers.update({"Authorization": f"Bearer {tok}", "Content-Type": "application/json"})
                    print(f"  Authenticated (PAT).")
                    return s, base
        except requests.exceptions.ConnectionError:
            continue

    s = requests.Session(); s.verify = verify_ssl; s.auth = (username, password)
    s.headers["Content-Type"] = "application/json"
    for test in [f"{base}/api/controller/v2/me/"]:
        try:
            if s.get(test).status_code == 200:
                print(f"  Authenticated (basic).")
                return s, base
        except: pass

    sys.exit(f"ERROR: Could not authenticate to {gateway_url}")


def build_session(args):
    if args.gateway:
        if not args.username or not args.password:
            sys.exit("ERROR: --gateway requires --username and --password.")
        session, base = authenticate_via_gateway(args.gateway, args.username, args.password, args.verify_ssl)
        return session, base, True
    if not args.controller:
        sys.exit("ERROR: Provide --gateway or --controller.")
    session = requests.Session()
    session.verify = args.verify_ssl
    if args.token:
        session.headers["Authorization"] = f"Bearer {args.token}"
    elif args.username and args.password:
        session.auth = (args.username, args.password)
    else:
        sys.exit("ERROR: Provide --token or --username/--password.")
    session.headers["Content-Type"] = "application/json"
    return session, args.controller.rstrip("/"), False


def api_base(base_url, via_gateway):
    return f"{base_url}/api/controller/v2" if via_gateway else f"{base_url}/api/v2"


# ============================================================================
# API helpers
# ============================================================================

def paginated_get(session, url, base_url, params=None, max_pages=None):
    page = 0
    while url:
        page += 1
        if max_pages and page > max_pages:
            break
        resp = session.get(url, params=params if page == 1 else None)
        if resp.status_code in (401, 403):
            sys.exit(f"ERROR: Auth failed (HTTP {resp.status_code}).")
        resp.raise_for_status()
        data = resp.json()
        yield from data.get("results", [])
        url = ensure_absolute_url(data.get("next"), base_url)


# ============================================================================
# Event analysis engine
# ============================================================================

def analyse_event(fqcn, event_data):
    """
    Analyse a single runner_on_ok event's data against what the jq query expects.

    Returns a diagnostic dict with:
        status: "OK", "MISSING_ROOT_KEY", "NULL_ROOT_KEY", "EMPTY_CONTAINER",
                "MISSING_ID_FIELD", "NO_RES", "UNKNOWN_MODULE", "HEURISTIC_OK",
                "HEURISTIC_NO_IDS", "NO_DATA_EXPECTED"
        details: human-readable explanation
        extracted: the node data that would be extracted (if OK)
    """
    res = event_data.get("res")
    if res is None:
        return {
            "status": "NO_RES",
            "details": "event_data.res is missing on a runner_on_ok event — module returned no data.",
            "extracted": None,
        }

    expectation = QUERY_EXPECTATIONS.get(fqcn)

    if expectation:
        return _analyse_with_expectation(fqcn, res, expectation)
    else:
        return _analyse_heuristic(fqcn, res)


def _analyse_with_expectation(fqcn, res, exp):
    """Analyse res against a known query expectation."""
    root_key = exp["root_key"]
    container = exp["container"]
    id_fields = exp["id_fields"]

    # For modules where query accesses top-level (root_key=None)
    if root_key is None:
        data = res
    else:
        if root_key not in res:
            available = [k for k in res.keys() if k not in ("changed", "invocation", "failed", "msg",
                                                              "deprecations", "warnings", "diff",
                                                              "_ansible_no_log", "ansible_facts",
                                                              "_ansible_delegated_vars")]
            return {
                "status": "MISSING_ROOT_KEY",
                "details": (
                    f"Query expects .{root_key} but it's not in the module return data.\n"
                    f"  Available data keys: {list(res.keys())}\n"
                    f"  Non-ansible keys: {available}\n"
                    f"  Expected: {exp['description']}"
                ),
                "expected_key": root_key,
                "available_keys": list(res.keys()),
                "non_ansible_keys": available,
                "extracted": None,
            }

        data = res[root_key]
        if data is None:
            return {
                "status": "NULL_ROOT_KEY",
                "details": (
                    f"Query accesses .{root_key} but it is null.\n"
                    f"  The jq 'select(. != null)' filter will skip this.\n"
                    f"  This usually means the module ran but returned no data for this field."
                ),
                "expected_key": root_key,
                "extracted": None,
            }

    # Check container type
    if container == "list":
        if not isinstance(data, list):
            return {
                "status": "WRONG_CONTAINER_TYPE",
                "details": (
                    f"Query expects .{root_key}[] (list) but got {type(data).__name__}.\n"
                    f"  The jq iteration (.[] ) will fail on a non-array value."
                ),
                "expected_key": root_key,
                "actual_type": type(data).__name__,
                "extracted": None,
            }
        if len(data) == 0:
            return {
                "status": "EMPTY_CONTAINER",
                "details": (
                    f"Query expects .{root_key}[] but the array is empty.\n"
                    f"  No items to iterate — jq produces no output."
                ),
                "expected_key": root_key,
                "extracted": None,
            }
        items = data
    elif container == "dict":
        items = [data]
    else:
        items = [data] if isinstance(data, dict) else data if isinstance(data, list) else [data]

    # Check for identifier fields
    extracted = []
    issues = []

    for i, item in enumerate(items if isinstance(items, list) else [items]):
        if not isinstance(item, dict):
            issues.append(f"  Item {i}: not a dict ({type(item).__name__})")
            continue

        found_id = None
        for id_field in id_fields:
            if id_field in item and item[id_field] is not None:
                found_id = (id_field, item[id_field])
                break

        if found_id:
            node = {
                "name": str(found_id[1]),
                "id_field": found_id[0],
                "id_value": found_id[1],
            }
            all_ids = {f: item.get(f) for f in id_fields if f in item and item[f] is not None}
            node["all_identifiers"] = all_ids
            extracted.append(node)
        else:
            available_fields = list(item.keys())
            issues.append(
                f"  Item {i}: No identifier field found.\n"
                f"    Looked for: {id_fields}\n"
                f"    Available: {available_fields}"
            )

    if extracted and not issues:
        return {
            "status": "OK",
            "details": f"Would extract {len(extracted)} node(s) successfully.",
            "extracted": extracted,
        }
    elif extracted and issues:
        return {
            "status": "PARTIAL",
            "details": (
                f"Extracted {len(extracted)} node(s) but {len(issues)} items had issues:\n"
                + "\n".join(issues)
            ),
            "extracted": extracted,
        }
    else:
        return {
            "status": "MISSING_ID_FIELD",
            "details": (
                f"Data structure looks correct but no identifier fields found.\n"
                f"  Query looks for: {id_fields}\n"
                + "\n".join(issues)
            ),
            "extracted": None,
        }


def _analyse_heuristic(fqcn, res):
    """Heuristic analysis for modules not in our expectations map."""
    data_keys = [k for k in res.keys() if k not in (
        "changed", "invocation", "failed", "msg", "deprecations",
        "warnings", "diff", "_ansible_no_log", "ansible_facts",
        "_ansible_delegated_vars",
        "stdout", "stderr", "rc", "start", "end", "delta", "cmd",
    )]

    if not data_keys:
        return {
            "status": "HEURISTIC_NO_DATA",
            "details": (
                f"Module {fqcn} is not in our known expectations.\n"
                f"  res keys: {list(res.keys())}\n"
                f"  No meaningful data keys found after filtering ansible internals."
            ),
            "extracted": None,
        }

    found_nodes = []
    for key in data_keys:
        val = res[key]
        if isinstance(val, list) and val and isinstance(val[0], dict):
            for item in val:
                for id_field in ID_FIELD_PRIORITY:
                    if id_field in item and item[id_field] is not None:
                        found_nodes.append({
                            "root_key": key,
                            "id_field": id_field,
                            "id_value": item[id_field],
                            "container": "list",
                        })
                        break
        elif isinstance(val, dict):
            for id_field in ID_FIELD_PRIORITY:
                if id_field in val and val[id_field] is not None:
                    found_nodes.append({
                        "root_key": key,
                        "id_field": id_field,
                        "id_value": val[id_field],
                        "container": "dict",
                    })
                    break

    if found_nodes:
        return {
            "status": "HEURISTIC_OK",
            "details": (
                f"Module {fqcn} is not in our known map, but heuristic found identifiers.\n"
                f"  A query could potentially extract these nodes."
            ),
            "extracted": found_nodes,
        }
    else:
        return {
            "status": "HEURISTIC_NO_IDS",
            "details": (
                f"Module {fqcn} is not in our known map.\n"
                f"  Data keys: {data_keys}\n"
                f"  No identifiable node fields found in any data key."
            ),
            "extracted": None,
        }


# ============================================================================
# Job processing
# ============================================================================

def process_job(session, base, base_url, via_gw, job_id, verbose=False):
    """Fetch events for a job and run diagnostic analysis."""
    ab = api_base(base, via_gw)

    job_resp = session.get(f"{ab}/jobs/{job_id}/")
    if job_resp.status_code == 404:
        return {"error": f"Job {job_id} not found"}
    if job_resp.status_code in (401, 403):
        return {"error": f"Auth failed for job {job_id}"}
    job_resp.raise_for_status()
    job_info = job_resp.json()

    print(f"\n  Job {job_id}: {job_info.get('name', 'N/A')}")
    print(f"  Status: {job_info.get('status')} | Finished: {job_info.get('finished', 'N/A')}")

    # Fetch all events
    url = f"{ab}/jobs/{job_id}/job_events/"
    params = {"page_size": 200, "order_by": "counter"}

    events = []
    page = 0
    while url:
        page += 1
        resp = session.get(url, params=params if page == 1 else None)
        if resp.status_code != 200:
            break
        data = resp.json()
        events.extend(data.get("results", []))
        url = ensure_absolute_url(data.get("next"), base_url)
        print(f"    Fetched page {page} ({len(events)} events so far)", end="\r", flush=True)

    print(f"    Total events: {len(events)}                    ")

    # Filter to ONLY runner_on_ok events with relevant FQCNs.
    # AAP only processes runner_on_ok for indirect node counting.
    # runner_on_start has no res (module hasn't run yet).
    # runner_on_failed / runner_on_skipped are not processed.
    diagnostics = []
    fqcn_summary = {}
    skipped_event_types = {}

    for ev in events:
        event_type = ev.get("event", "")
        ed = ev.get("event_data", {})
        ra = ed.get("resolved_action", "")

        # Only care about known collection namespaces
        if not any(ra.startswith(ns) for ns in KNOWN_NAMESPACES):
            continue

        # Track non-ok event types for info but don't diagnose them
        if event_type not in PROCESSABLE_EVENT_TYPES:
            skipped_event_types[event_type] = skipped_event_types.get(event_type, 0) + 1
            continue

        diag = analyse_event(ra, ed)
        diag["fqcn"] = ra
        diag["event_type"] = event_type
        diag["counter"] = ev.get("counter")
        diag["host"] = ed.get("host", "")

        if verbose:
            diag["raw_res_keys"] = list(ed.get("res", {}).keys()) if isinstance(ed.get("res"), dict) else None

        diagnostics.append(diag)

        if ra not in fqcn_summary:
            fqcn_summary[ra] = {"ok": 0, "fail": 0, "events": 0, "issues": []}
        fqcn_summary[ra]["events"] += 1

        if diag["status"] in ("OK", "HEURISTIC_OK", "PARTIAL"):
            fqcn_summary[ra]["ok"] += 1
        else:
            fqcn_summary[ra]["fail"] += 1
            fqcn_summary[ra]["issues"].append(diag["status"])

    return {
        "job_id": job_id,
        "job_name": job_info.get("name", ""),
        "job_status": job_info.get("status", ""),
        "finished": job_info.get("finished", ""),
        "total_events": len(events),
        "relevant_runner_on_ok_events": len(diagnostics),
        "skipped_event_types": skipped_event_types,
        "fqcn_summary": fqcn_summary,
        "diagnostics": diagnostics,
    }


def discover_jobs(session, base, base_url, via_gw, days=7, limit=5):
    """Find recent jobs with relevant module events."""
    ab = api_base(base, via_gw)
    since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000000")

    print(f"  Looking for successful jobs since {since[:10]} ...")

    url = f"{ab}/jobs/"
    params = {"page_size": 50, "order_by": "-finished", "finished__gte": since, "status": "successful"}

    all_jobs = list(paginated_get(session, url, base_url, params))
    print(f"  Found {len(all_jobs)} successful jobs.")

    seen_templates = {}
    relevant = []

    for job in all_jobs:
        jid = job.get("id")
        name = job.get("name", "")

        if name in seen_templates:
            continue

        sample_url = f"{ab}/jobs/{jid}/job_events/"
        sample_params = {"page_size": 100, "order_by": "counter", "event": "runner_on_ok"}
        try:
            resp = session.get(sample_url, params=sample_params)
            if resp.status_code != 200:
                continue
            results = resp.json().get("results", [])

            matched = set()
            for ev in results:
                ra = ev.get("event_data", {}).get("resolved_action", "")
                if any(ra.startswith(ns) for ns in KNOWN_NAMESPACES):
                    matched.add(ra)

            if matched:
                seen_templates[name] = jid
                relevant.append({"id": jid, "name": name, "fqcns": sorted(matched)})
                print(f"    Job {jid} ({name}): {', '.join(sorted(matched))}")

                if len(relevant) >= limit:
                    break
        except Exception:
            continue

    return relevant


# ============================================================================
# Report printer
# ============================================================================

def print_report(results):
    """Print a clear diagnostic report."""
    print(f"\n{'=' * 78}")
    print(f"  INDIRECT NODE COUNTING DIAGNOSTIC REPORT")
    print(f"{'=' * 78}")

    all_ok = True
    any_relevant = False

    for job_result in results:
        if "error" in job_result:
            print(f"\n  Job {job_result.get('job_id', '?')}: {job_result['error']}")
            continue

        jid = job_result["job_id"]
        jname = job_result["job_name"]
        relevant_count = job_result["relevant_runner_on_ok_events"]
        skipped = job_result.get("skipped_event_types", {})

        print(f"\n{'─' * 78}")
        print(f"  JOB {jid}: {jname}")
        print(f"  Status: {job_result['job_status']} | Total events: {job_result['total_events']} | "
              f"Analysed (runner_on_ok): {relevant_count}")
        if skipped:
            skipped_str = ", ".join(f"{k}: {v}" for k, v in sorted(skipped.items()))
            print(f"  Skipped (not processed by AAP): {skipped_str}")
        print(f"{'─' * 78}")

        if not job_result["fqcn_summary"]:
            print(f"  No relevant runner_on_ok events found in this job.")
            continue

        any_relevant = True

        for fqcn, summary in sorted(job_result["fqcn_summary"].items()):
            total = summary["events"]
            ok = summary["ok"]
            fail = summary["fail"]

            if fail > 0:
                all_ok = False
                icon = "[FAIL]"
            else:
                icon = "[OK]  "

            print(f"\n  {icon} {fqcn}")
            print(f"         Events: {total} | Would extract: {ok} | Would fail: {fail}")

            if fail > 0:
                issue_counts = {}
                for issue in summary["issues"]:
                    issue_counts[issue] = issue_counts.get(issue, 0) + 1
                for issue, count in sorted(issue_counts.items(), key=lambda x: -x[1]):
                    print(f"         Failure: {issue} (x{count})")

        # Show detailed diagnostics for failures
        failures = [d for d in job_result["diagnostics"]
                    if d["status"] not in ("OK", "HEURISTIC_OK", "PARTIAL")]

        if failures:
            seen_issues = set()
            print(f"\n  FAILURE DETAILS (one example per issue type):")

            for diag in failures:
                issue_key = f"{diag['fqcn']}|{diag['status']}"
                if issue_key in seen_issues:
                    continue
                seen_issues.add(issue_key)

                print(f"\n    FQCN: {diag['fqcn']}")
                print(f"    Event: {diag['event_type']} #{diag.get('counter', '?')} (host: {diag.get('host', '?')})")
                print(f"    Status: {diag['status']}")

                for line in diag["details"].split("\n"):
                    print(f"      {line}")

                if diag.get("raw_res_keys"):
                    print(f"      res keys: {diag['raw_res_keys']}")

    # Overall verdict
    print(f"\n{'=' * 78}")
    if not any_relevant:
        print("  VERDICT: No relevant runner_on_ok events found to analyse.")
        print("  Ensure jobs are running modules from collections with event_query.yml files.")
    elif all_ok:
        print("  VERDICT: Event data looks correct for all modules.")
        print("  If main_indirectmanagednodeaudit is still empty, the issue is likely:")
        print("    1. The event_query.yml in the collection doesn't match these modules")
        print("    2. The rollup task (save_indirect_host_entries) isn't running")
        print("    3. FEATURE_INDIRECT_NODE_COUNTING_ENABLED is not true")
        print("    4. The event_query rows in main_eventquery have wrong query syntax")
    else:
        print("  VERDICT: Found issues that would cause jq query failures.")
        print("  The module return data doesn't match what the queries expect.")
        print("  This usually means the event_query.yml in the collection needs to be")
        print("  regenerated for the installed collection version.")
    print(f"{'=' * 78}")


# ============================================================================
# Main
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Diagnose AAP Indirect Managed Node Counting failures.",
        epilog="""
Examples:
  # Diagnose a specific job:
  %(prog)s 40754 -g https://gw.example.com -u admin -p secret --no-verify-ssl

  # Auto-discover recent jobs (last 7 days, up to 5 unique templates):
  %(prog)s --discover -g https://gw.example.com -u admin -p secret --no-verify-ssl

  # Discover more:
  %(prog)s --discover --days 14 --limit 10 -g https://gw.example.com -u admin -p secret --no-verify-ssl
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("job_id", type=int, nargs="?", help="Specific job ID to diagnose.")
    parser.add_argument("--discover", action="store_true", help="Auto-discover recent relevant jobs.")
    parser.add_argument("--days", type=int, default=7, help="Days to look back (default: 7).")
    parser.add_argument("--limit", type=int, default=5, help="Max unique job templates to analyse (default: 5).")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show raw res keys in output.")
    parser.add_argument("--output", "-o", help="Save full results to JSON file.")

    conn = parser.add_mutually_exclusive_group()
    conn.add_argument("--gateway", "-g", default=os.environ.get("GATEWAY_HOST", ""))
    conn.add_argument("--controller", "-c", default=os.environ.get("CONTROLLER_HOST", ""))

    parser.add_argument("--token", "-t", default=os.environ.get("CONTROLLER_TOKEN", ""))
    parser.add_argument("--username", "-u", default=os.environ.get("CONTROLLER_USERNAME", ""))
    parser.add_argument("--password", "-p", default=os.environ.get("CONTROLLER_PASSWORD", ""))
    parser.add_argument("--no-verify-ssl", action="store_true",
                        default=os.environ.get("CONTROLLER_VERIFY_SSL", "true").lower() == "false")

    args = parser.parse_args()
    args.verify_ssl = not args.no_verify_ssl

    if not args.discover and args.job_id is None:
        parser.error("Provide a job_id or use --discover.")

    if not args.gateway and not args.controller:
        if os.environ.get("GATEWAY_HOST"): args.gateway = os.environ["GATEWAY_HOST"]
        elif os.environ.get("CONTROLLER_HOST"): args.controller = os.environ["CONTROLLER_HOST"]
        else: sys.exit("ERROR: Provide --gateway or --controller.")

    if not args.verify_ssl:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    via_gw = bool(args.gateway)
    target = args.gateway if via_gw else args.controller

    print(f"{'Gateway' if via_gw else 'Controller'}: {target}")
    session, base_url, via_gw = build_session(args)
    print(f"API: {api_base(base_url, via_gw)}\n")

    if args.discover:
        print(f"Discovering relevant jobs (last {args.days} day(s), limit {args.limit}) ...")
        jobs_to_analyse = discover_jobs(session, base_url, base_url, via_gw, args.days, args.limit)
        if not jobs_to_analyse:
            print("\nNo jobs with relevant module events found.")
            sys.exit(0)
        job_ids = [j["id"] for j in jobs_to_analyse]
        print(f"\nWill analyse {len(job_ids)} job(s): {job_ids}")
    else:
        job_ids = [args.job_id]

    results = []
    for jid in job_ids:
        result = process_job(session, base_url, base_url, via_gw, jid, args.verbose)
        results.append(result)

    print_report(results)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\nFull results saved to: {args.output}")


if __name__ == "__main__":
    main()
