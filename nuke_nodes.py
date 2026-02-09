#!/usr/bin/python3

import requests
import subprocess
import argparse
import time
import sys
import os
import logging
import json
import random

# Set up logging
LOG_FILE = '/var/log/asterisk/nuke_nodes.log'
logging.basicConfig(filename=LOG_FILE, level=logging.DEBUG, format='%(asctime)s - %(message)s')

STATE_FILE = '/var/log/asterisk/nuke_nodes_state.json'

# Nodes that should never be disconnected or blocked.
WHITELISTED_NODES = set()

# Default locations checked when --whitelist is not provided explicitly.
DEFAULT_WHITELIST_PATHS = [
    "/root/whitelist.txt",
]

# Connection attempt handling
CONNECTION_DISCONNECT_THRESHOLD = 5
CONNECTION_BAN_THRESHOLD = 6
CONNECTION_ATTEMPT_RESET_SECONDS = 900  # Reset attempt counter after 15 minutes of inactivity
DEFAULT_NODE_FETCH_DELAY_SECONDS = 0.40
DEFAULT_NODE_FETCH_JITTER_SECONDS = 0.20

def log_message(message):
    """Logs a message to the log file and console."""
    logging.debug(message)
    print(message)  # Also print to console for immediate feedback

SUDO = "/usr/bin/sudo"  # Path to sudo
ASTERISK = "/usr/sbin/asterisk"  # Path to Asterisk binary
DB_FAMILY = "blacklist"  # Database family for blacklist

STATS_URL = "https://stats.allstarlink.org/api/stats/"

def load_list(file_path, quiet_missing=False):
    """Loads a list of node IDs from a text file."""
    try:
        with open(file_path, 'r') as file:
            return {line.strip() for line in file if line.strip()}
    except FileNotFoundError:
        if not quiet_missing:
            log_message("File not found: {}".format(file_path))
        return set()


def ensure_directory_exists(path):
    """Ensure the directory for the provided path exists."""
    directory = os.path.dirname(path)
    if directory and not os.path.exists(directory):
        try:
            os.makedirs(directory, exist_ok=True)
        except OSError as error:
            log_message("Failed to create directory {}: {}".format(directory, error))


def load_state():
    """Load the persistent node connection state from disk."""
    try:
        with open(STATE_FILE, 'r') as state_file:
            data = json.load(state_file)
            return {str(key): value for key, value in data.items()}
    except FileNotFoundError:
        log_message("State file not found: {}. Starting with empty state.".format(STATE_FILE))
    except json.JSONDecodeError as error:
        log_message("Failed to decode state file {}: {}. Resetting state.".format(STATE_FILE, error))
    except Exception as error:
        log_message("Unexpected error reading state file {}: {}".format(STATE_FILE, error))
    return {}


def is_whitelisted(node_id):
    """Return True when the node ID is in the global whitelist."""
    return str(node_id) in WHITELISTED_NODES


def save_state(state):
    """Persist the node connection state to disk."""
    try:
        ensure_directory_exists(STATE_FILE)
        with open(STATE_FILE, 'w') as state_file:
            json.dump(state, state_file)
    except Exception as error:
        log_message("Failed to save state to {}: {}".format(STATE_FILE, error))


def load_whitelist(cli_whitelist_path):
    """Load whitelist entries from the CLI path or default locations."""
    candidate_paths = []
    if cli_whitelist_path:
        candidate_paths.append(cli_whitelist_path)
    for default_path in DEFAULT_WHITELIST_PATHS:
        if default_path not in candidate_paths:
            candidate_paths.append(default_path)

    for path in candidate_paths:
        quiet_missing = path in DEFAULT_WHITELIST_PATHS and path != cli_whitelist_path
        entries = load_list(path, quiet_missing=quiet_missing)
        if os.path.exists(path):
            log_message("Loaded whitelist from {}: {}".format(path, sorted(entries)))
            return entries
        if entries:
            # File may exist temporarily or be virtual; still honour entries.
            log_message("Loaded whitelist entries: {}".format(sorted(entries)))
            return entries

    if cli_whitelist_path:
        log_message("Whitelist file {} not found. Proceeding without whitelist.".format(cli_whitelist_path))
    else:
        log_message("No whitelist file found in default locations. Proceeding without whitelist.")
    return set()

def normalize_loop_interval(requested_interval):
    """Return a safe loop interval; never abort in daemon mode because of a low value."""
    if requested_interval is None:
        return 60
    if requested_interval < 10:
        log_message(
            "Loop interval {}s is below minimum. Using 10s to keep service running.".format(requested_interval)
        )
        return 10
    return requested_interval



def set_node_event(connection_state, node_id, event_name):
    """Record node event state and return True when the event changed."""
    node_key = str(node_id)
    node_state = connection_state.setdefault(node_key, {})
    previous_event = node_state.get('last_logged_event')
    node_state['last_logged_event'] = event_name
    return previous_event != event_name

def pace_api_request(last_request_time, min_delay_seconds, jitter_seconds):
    """Sleep as needed so node-level stats requests are spread out over time."""
    now = time.time()
    elapsed = now - last_request_time
    jitter = random.uniform(0, max(0.0, jitter_seconds))
    wait_for = max(0.0, min_delay_seconds + jitter - elapsed)
    if wait_for > 0:
        time.sleep(wait_for)
        now = time.time()
    return now


def handle_connection_attempt(node_id, connection_state, initial_node_id, timestamp):
    """Handle repeated connect/disconnect behavior for a node."""
    if is_whitelisted(node_id):
        if connection_state.pop(node_id, None):
            log_message("Node {} is whitelisted. Clearing connection tracking state.".format(node_id))
        return False

    node_state = connection_state.setdefault(node_id, {
        'connection_attempts': 0,
        'is_connected': False,
        'banned': False,
        'last_connected_at': None,
        'last_disconnected_at': None,
        'last_seen_at': None,
        'last_logged_event': None,
    })

    node_state['last_seen_at'] = timestamp

    if node_state.get('banned'):
        if not is_node_blocked(node_id):
            log_message(
                "Node {} was previously banned but is no longer blocked. Clearing ban state.".format(node_id)
            )
            node_state['banned'] = False
            node_state['connection_attempts'] = 0
            node_state['last_disconnected_at'] = None
        else:
            if set_node_event(connection_state, node_id, 'already_banned'):
                log_message("Node {} is already banned due to excessive reconnects.".format(node_id))
            return True

    if node_state.get('is_connected'):
        return False

    last_disconnected_at = node_state.get('last_disconnected_at')
    if last_disconnected_at:
        idle_seconds = timestamp - last_disconnected_at
        if idle_seconds > CONNECTION_ATTEMPT_RESET_SECONDS and node_state.get('connection_attempts'):
            log_message(
                "Resetting connection attempt counter for node {} after {:.0f} seconds of inactivity.".format(
                    node_id, idle_seconds
                )
            )
            node_state['connection_attempts'] = 0

    node_state['connection_attempts'] = node_state.get('connection_attempts', 0) + 1
    node_state['is_connected'] = True
    node_state['last_connected_at'] = timestamp
    attempts = node_state['connection_attempts']
    if set_node_event(connection_state, node_id, 'connected'):
        log_message("Node {} connected. Tracking reconnect behavior for this session.".format(node_id))
    log_message("Node {} connection attempt count: {}".format(node_id, attempts))

    if attempts >= CONNECTION_BAN_THRESHOLD:
        reason = "Excessive connect/disconnect cycles detected. Node banned."
        update_blocked_node(node_id, reason)
        disconnect_node(node_id, initial_node_id, reason)
        node_state['is_connected'] = False
        node_state['banned'] = True
        node_state['last_disconnected_at'] = timestamp
        log_message("Node {} has been disconnected and banned after {} attempts.".format(node_id, attempts))
        return True

    if attempts >= CONNECTION_DISCONNECT_THRESHOLD:
        reason = "Excessive connect/disconnect cycles detected. Node disconnected."
        disconnect_node(node_id, initial_node_id, reason)
        node_state['is_connected'] = False
        node_state['last_disconnected_at'] = timestamp
        log_message("Node {} disconnected after {} attempts.".format(node_id, attempts))
        return True

    return False


def update_disconnection_status(current_links, connection_state, timestamp=None):
    """Update the state for nodes that are no longer connected."""
    current_link_set = {str(node) for node in current_links}
    observed_at = timestamp if timestamp is not None else time.time()
    for node_id, node_state in list(connection_state.items()):
        if is_whitelisted(node_id):
            if connection_state.pop(node_id, None) is not None:
                log_message("Node {} is whitelisted. Removing it from connection tracking.".format(node_id))
            continue

        if node_id in current_link_set:
            node_state['last_seen_at'] = observed_at
            continue

        if node_state.get('is_connected'):
            node_state['is_connected'] = False
            node_state['last_disconnected_at'] = observed_at
            node_state['last_seen_at'] = observed_at
            log_message("Node {} disconnected. Total connection attempts recorded: {}".format(
                node_id, node_state.get('connection_attempts', 0)
            ))


def update_blocked_node(node_id, comment=""):
    """Update the Asterisk database to block the node."""
    if is_whitelisted(node_id):
        log_message("Node {} is whitelisted. Skipping block request.".format(node_id))
        return
    try:
        sanitized_comment = comment.replace(" ", "_")
        command = "{} {} -rx \"database put {} {} {}\"".format(SUDO, ASTERISK, DB_FAMILY, node_id, sanitized_comment)
        log_message("Running command: {}".format(command))
        subprocess.run(command, shell=True, check=True)
        log_message("Blocked node {} with comment: {}".format(node_id, sanitized_comment))
    except subprocess.CalledProcessError as e:
        log_message("Failed to block node {}: {}".format(node_id, e))


def is_node_blocked(node_id):
    """Check if the node is currently blocked in the Asterisk database."""
    if is_whitelisted(node_id):
        return False
    command = "{} {} -rx \"database get {} {}\"".format(SUDO, ASTERISK, DB_FAMILY, node_id)
    try:
        result = subprocess.run(
            command,
            shell=True,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except Exception as error:
        log_message("Failed to check block status for node {}: {}".format(node_id, error))
        return True

    output = (result.stdout or "") + (result.stderr or "")
    if "Database entry not found" in output:
        return False
    if "Value:" in output:
        return True

    log_message("Unexpected block status response for node {}: {}".format(node_id, output.strip()))
    return False


def disconnect_node(node_id, initial_node_id, reason=""):
    """Disconnect a node using Asterisk rpt command."""
    if is_whitelisted(node_id):
        log_message("Node {} is whitelisted. Skipping disconnect request.".format(node_id))
        return
    try:
        command = "{} {} -rx \"rpt fun {} *1{}\"".format(SUDO, ASTERISK, initial_node_id, node_id)
        log_message("Disconnecting node {} from {}. Reason: {}".format(node_id, initial_node_id, reason))
        subprocess.run(command, shell=True, check=True)
        log_message("Node {} disconnected from {} successfully.".format(node_id, initial_node_id))
    except subprocess.CalledProcessError as e:
        log_message("Failed to disconnect node {} from {}: {}".format(node_id, initial_node_id, e))

def fetch_data(url, max_retries=10, backoff_factor=2, compact_not_found=False):
    """Fetch data from URL with retries for rate limiting and optional compact 404 logging."""
    retries = 0
    while retries < max_retries:
        try:
            response = requests.get(url)
            if response.status_code == 200:
                log_message("Successfully fetched data from URL: {}".format(url))
                return response.json()
            elif response.status_code == 429:
                retry_after = response.headers.get("Retry-After")
                if retry_after:
                    wait_time = int(retry_after)
                else:
                    wait_time = backoff_factor ** retries
                log_message("429 Too Many Requests. Retrying in {} seconds... (Retry-After: {})".format(wait_time, retry_after))
                time.sleep(wait_time)
                retries += 1
            elif response.status_code == 404 and compact_not_found:
                return None
            else:
                log_message("Failed to fetch data. Status code: {}. URL: {}. Response headers: {}".format(
                    response.status_code, url, response.headers
                ))
                return None
        except Exception as e:
            log_message("Error fetching data from {}: {}".format(url, e))
            return None
    log_message("Max retries reached for URL: {}".format(url))
    return None

def is_stats_enabled(node_id):
    """Check if the node has stats enabled and is actively reporting on stats.allstarlink.org."""
    url = STATS_URL + str(node_id)
    data = fetch_data(url)
    if data:
        stats_enabled = data.get('stats', {}).get('data', {}).get('enabled', False)
        last_reported = data.get('stats', {}).get('data', {}).get('lastseen', None)
        if stats_enabled and last_reported:
            log_message("Node {} is reporting stats and active.".format(node_id))
            return True
    log_message("Node {} is either not reporting stats or inactive.".format(node_id))
    return False

def detect_crosslinking(node_id, links, whitelisted_nodes, initial_node_id):
    """Detect crosslinking for a given node based on its connections."""
    allowed_nodes = {str(initial_node_id), str(node_id)} | {str(node) for node in whitelisted_nodes}
    log_message(
        "Node {} checking links against whitelist: {}".format(node_id, sorted(allowed_nodes))
    )
    unexpected_nodes = [link for link in links if str(link) not in allowed_nodes]
    log_message("Node {} connected links: {}".format(node_id, links))
    log_message("Node {} unexpected connections: {}".format(node_id, unexpected_nodes))
    if unexpected_nodes:
        return True, unexpected_nodes
    return False, []

def detect_area_restrictions(node_id, area_restrictions):
    """Check if a node is in a restricted area."""
    log_message("Checking area restrictions for node {}.".format(node_id))
    if node_id in area_restrictions:
        log_message("Node {} is in a restricted area.".format(node_id))
        return True
    log_message("Node {} is not in a restricted area.".format(node_id))
    return False

def main():
    parser = argparse.ArgumentParser(description='Fetch and process node data.')
    parser.add_argument('initial_node_id', type=str, help='Initial Node ID to fetch data for')
    parser.add_argument('--quiet', action='store_true', help='Suppress output')
    parser.add_argument('--loop', type=int, help='Loop the script with the specified interval in seconds.')
    parser.add_argument('--area_restrictions', type=str, help='Path to the area restrictions file')
    parser.add_argument('--whitelist', type=str, help='Path to the whitelist file')
    parser.add_argument('--run-once', action='store_true', help='Process a single iteration and exit.')
    parser.add_argument(
        '--node-fetch-delay',
        type=float,
        default=DEFAULT_NODE_FETCH_DELAY_SECONDS,
        help='Minimum seconds between per-node stats API calls (default: {}).'.format(
            DEFAULT_NODE_FETCH_DELAY_SECONDS
        ),
    )
    parser.add_argument(
        '--node-fetch-jitter',
        type=float,
        default=DEFAULT_NODE_FETCH_JITTER_SECONDS,
        help='Additional random delay added to per-node API pacing (default: {}).'.format(
            DEFAULT_NODE_FETCH_JITTER_SECONDS
        ),
    )
    args = parser.parse_args()

    if args.run_once and args.loop is not None:
        print("Error: --loop cannot be used with --run-once.")
        sys.exit(1)

    if args.node_fetch_delay < 0:
        print("Error: --node-fetch-delay must be >= 0.")
        sys.exit(1)

    if args.node_fetch_jitter < 0:
        print("Error: --node-fetch-jitter must be >= 0.")
        sys.exit(1)

    if args.run_once:
        loop_interval = None
    else:
        loop_interval = normalize_loop_interval(args.loop)

    area_restrictions = load_list(args.area_restrictions) if args.area_restrictions else set()
    whitelist_entries = load_whitelist(args.whitelist)

    global WHITELISTED_NODES
    WHITELISTED_NODES = {str(node_id) for node_id in whitelist_entries}

    initial_url = STATS_URL + args.initial_node_id

    connection_state = load_state()
    last_node_fetch_time = 0.0
    for node_id in list(connection_state.keys()):
        if is_whitelisted(node_id):
            connection_state.pop(node_id, None)
            log_message("Node {} is whitelisted at startup. Removed from tracked state.".format(node_id))

    while True:
        try:
            initial_data = fetch_data(initial_url)

            if not initial_data:
                if loop_interval is None:
                    log_message("No valid data retrieved for the initial node. Exiting after single pass.")
                    save_state(connection_state)
                    break

                log_message("No valid data retrieved for the initial node. Waiting {} seconds before retrying.".format(loop_interval))
                save_state(connection_state)
                time.sleep(loop_interval)
                continue

            links = initial_data.get('stats', {}).get('data', {}).get('links', [])
            observation_time = time.time()
            log_message("Initial node {} connected links: {}".format(args.initial_node_id, links))

            update_disconnection_status(links, connection_state, observation_time)

            for node_id in links:
                node_id_str = str(node_id)

                if is_whitelisted(node_id_str):
                    log_message("Node {} is in the whitelist. It will remain connected.".format(node_id))
                    continue

                if handle_connection_attempt(node_id_str, connection_state, args.initial_node_id, observation_time):
                    save_state(connection_state)
                    continue

                node_url = "https://stats.allstarlink.org/api/stats/" + str(node_id)
                last_node_fetch_time = pace_api_request(
                    last_node_fetch_time,
                    args.node_fetch_delay,
                    args.node_fetch_jitter,
                )
                node_data = fetch_data(node_url, compact_not_found=True)

                if not node_data:
                    if set_node_event(connection_state, node_id_str, 'no_data'):
                        log_message("No data available for node {}. Skipping to next node.".format(node_id))
                    continue

                set_node_event(connection_state, node_id_str, 'data_available')

                # Check if stats field is None
                stats = node_data.get("stats", None)
                if stats is None:
                    log_message("Node {} stats field is None. Treating as stats not enabled. Disconnecting and blocking.".format(node_id))
                    reason = "Stat reporting disabled. Disconnecting and blocking node."
                    update_blocked_node(node_id, reason)
                    disconnect_node(node_id, args.initial_node_id, reason)
                    connection_state.pop(node_id_str, None)
                    log_message("Blocked and disconnected node {}. Continuing to next node.".format(node_id))
                    save_state(connection_state)
                    continue

                # Check stats_enabled field
                stats_enabled = node_data.get("stats_enabled", True)

                # Detect crosslinking
                current_links = node_data.get('stats', {}).get('data', {}).get('links', [])

                # Explicitly check if the node is only connected to the initial node
                if current_links == [args.initial_node_id]:
                    log_message("Node {} is only connected to initial node {} and is not providing crosslink. It will remain connected.".format(node_id, args.initial_node_id))
                    continue

                crosslink_detected, unexpected_nodes = detect_crosslinking(
                    node_id, current_links, WHITELISTED_NODES, args.initial_node_id
                )


                if crosslink_detected:
                    log_message("Crosslink detected on node {} with unexpected nodes: {}".format(node_id, unexpected_nodes))
                    reason = "Crosslinking detected with unexpected nodes: {}".format(unexpected_nodes)
                    update_blocked_node(node_id, reason)
                    disconnect_node(node_id, args.initial_node_id, reason)
                    connection_state.pop(node_id_str, None)
                    log_message("Disconnected and blocked node {} due to crosslinking. Continuing to next node.".format(node_id))
                    save_state(connection_state)
                    continue

                if stats_enabled is True:
                    if set_node_event(connection_state, node_id_str, 'stats_enabled_true'):
                        log_message("Node {} has stats explicitly enabled. It will remain connected.".format(node_id))
                    continue

                # Treat stats_enabled=None as disabled if stats is missing
                if stats_enabled is None:
                    log_message("Node {} stats_enabled is None. Treating as stats not enabled. Disconnecting and blocking.".format(node_id))
                    reason = "Stat reporting disabled or missing. Disconnecting and blocking node."
                    update_blocked_node(node_id, reason)
                    disconnect_node(node_id, args.initial_node_id, reason)
                    connection_state.pop(node_id_str, None)
                    log_message("Blocked and disconnected node {}. Continuing to next node.".format(node_id))
                    save_state(connection_state)
                    continue

                # Block and disconnect nodes explicitly reporting stats_enabled: False
                if stats_enabled is False:
                    log_message("Node {} stats_enabled is explicitly False. Disconnecting and blocking.".format(node_id))
                    reason = "Stat reporting disabled. Disconnecting and blocking node."
                    update_blocked_node(node_id, reason)
                    disconnect_node(node_id, args.initial_node_id, reason)
                    connection_state.pop(node_id_str, None)
                    log_message("Blocked and disconnected node {}. Continuing to next node.".format(node_id))
                    save_state(connection_state)
                    continue

            update_disconnection_status(links, connection_state, time.time())
            save_state(connection_state)

            if loop_interval is None:
                break

            time.sleep(loop_interval)
        except Exception as error:
            log_message("Unexpected runtime error in main loop: {}".format(error))
            save_state(connection_state)
            if loop_interval is None:
                raise
            time.sleep(loop_interval)

if __name__ == "__main__":
    main()
