#!/usr/bin/python3

import requests
import subprocess
import argparse
import time
import sys
import os
import logging
from collections import deque

# Set up logging
LOG_FILE = '/var/log/asterisk/nuke_nodes.log'
logging.basicConfig(filename=LOG_FILE, level=logging.DEBUG, format='%(asctime)s - %(message)s')

def log_message(message):
    """Logs a message to the log file and console."""
    logging.debug(message)
    print(message)  # Also print to console for immediate feedback

SUDO = "/usr/bin/sudo"  # Path to sudo
ASTERISK = "/usr/sbin/asterisk"  # Path to Asterisk binary
DB_FAMILY = "blacklist"  # Database family for blacklist

# Threshold for repetitive banning allstar nodes when there is crosslinking and not reporting stats enabled
THRESHOLD = 2  # Number of events within the monitoring period
MONITOR_PERIOD = 60  # Monitoring period in seconds (e.g., 1 minute)

STATS_URL = "https://stats.allstarlink.org/api/stats/"

# Track repeated events for each node and action type within the monitoring period
event_history = {}


def _record_event(node_id, event_type):
    """Track events for nodes and determine if the threshold is met."""
    current_time = time.time()
    key = (str(node_id), event_type)
    history = event_history.setdefault(key, deque())
    history.append(current_time)

    while history and current_time - history[0] > MONITOR_PERIOD:
        history.popleft()

    if len(history) >= THRESHOLD:
        history.clear()
        return True
    return False

def load_list(file_path):
    """Loads a list of node IDs from a text file."""
    try:
        with open(file_path, 'r') as file:
            return {line.strip() for line in file}
    except FileNotFoundError:
        log_message("File not found: {}".format(file_path))
        return set()

def update_blocked_node(node_id, comment=""):
    """Update the Asterisk database to block the node."""
    try:
        sanitized_comment = comment.replace(" ", "_")
        command = "{} {} -rx \"database put {} {} {}\"".format(SUDO, ASTERISK, DB_FAMILY, node_id, sanitized_comment)
        log_message("Running command: {}".format(command))
        subprocess.run(command, shell=True, check=True)
        log_message("Blocked node {} with comment: {}".format(node_id, sanitized_comment))
    except subprocess.CalledProcessError as e:
        log_message("Failed to block node {}: {}".format(node_id, e))

def disconnect_node(node_id, initial_node_id, reason=""):
    """Disconnect a node using Asterisk rpt command."""
    try:
        command = "{} {} -rx \"rpt fun {} *1{}\"".format(SUDO, ASTERISK, initial_node_id, node_id)
        log_message("Disconnecting node {} from {}. Reason: {}".format(node_id, initial_node_id, reason))
        subprocess.run(command, shell=True, check=True)
        log_message("Node {} disconnected from {} successfully.".format(node_id, initial_node_id))
    except subprocess.CalledProcessError as e:
        log_message("Failed to disconnect node {} from {}: {}".format(node_id, initial_node_id, e))

def fetch_data(url, max_retries=10, backoff_factor=2):
    """Fetches data from the given URL with retry logic for handling rate limiting."""
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

def detect_crosslinking(node_id, links, whitelisted_nodes):
    """Detect crosslinking for a given node based on its connections."""
    log_message("Node {} checking links against whitelist: {}".format(node_id, whitelisted_nodes))
    unexpected_nodes = [link for link in links if str(link) not in whitelisted_nodes]
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
    args = parser.parse_args()

    if args.loop and args.loop < 10:
        print("Error: Loop interval must be at least 10 seconds.")
        sys.exit(1)

    area_restrictions = load_list(args.area_restrictions) if args.area_restrictions else set()
    whitelist = load_list(args.whitelist) if args.whitelist else set()

    initial_url = STATS_URL + args.initial_node_id

    while True:
        initial_data = fetch_data(initial_url)

        if initial_data:
            links = initial_data.get('stats', {}).get('data', {}).get('links', [])
            log_message("Initial node {} connected links: {}".format(args.initial_node_id, links))

            for node_id in links:
                log_message("Processing node ID: {}".format(node_id))

                if str(node_id) in whitelist:
                    log_message("Node {} is in the whitelist. It will remain connected.".format(node_id))
                    continue

                node_url = "https://stats.allstarlink.org/api/stats/" + str(node_id)
                node_data = fetch_data(node_url)

                if not node_data:
                    log_message("No data available for node {}. Skipping to next node.".format(node_id))
                    continue

                # Check if stats field is None
                stats = node_data.get("stats", None)
                if stats is None:
                    log_message("Node {} stats field is None. Treating as stats not enabled.".format(node_id))
                    if _record_event(node_id, "stats_not_enabled"):
                        reason = "Stat reporting disabled. Disconnecting and blocking node."
                        update_blocked_node(node_id, reason)
                        disconnect_node(node_id, args.initial_node_id, reason)
                        log_message("Blocked and disconnected node {}. Stopping further processing.".format(node_id))
                        return  # Stop further processing after blocking one node
                    log_message("Threshold not met for node {} stats-disabled event. Continuing monitoring.".format(node_id))
                    continue

                # Check stats_enabled field
                stats_enabled = node_data.get("stats_enabled", True)
                log_message("Node {} stats_enabled value: {}".format(node_id, stats_enabled))

                # Detect crosslinking
                current_links = node_data.get('stats', {}).get('data', {}).get('links', [])
                log_message("Node {} connected links: {}".format(node_id, current_links))

                # Explicitly check if the node is only connected to the initial node
                if current_links == [args.initial_node_id]:
                    log_message("Node {} is only connected to initial node {} and is not providing crosslink. It will remain connected.".format(node_id, args.initial_node_id))
                    continue

                crosslink_detected, unexpected_nodes = detect_crosslinking(node_id, current_links, whitelist)

                if crosslink_detected:
                    log_message("Crosslink detected on node {} with unexpected nodes: {}".format(node_id, unexpected_nodes))
                    if _record_event(node_id, "crosslinking"):
                        reason = "Crosslinking detected with unexpected nodes: {}".format(unexpected_nodes)
                        update_blocked_node(node_id, reason)
                        disconnect_node(node_id, args.initial_node_id, reason)
                        log_message("Disconnected and blocked node {} due to crosslinking.".format(node_id))
                        return  # Exit after handling a crosslink
                    log_message("Threshold not met for node {} crosslink event. Continuing monitoring.".format(node_id))
                    continue

                if stats_enabled is True:
                    log_message("Node {} has stats explicitly enabled. It will remain connected.".format(node_id))
                    continue

                # Treat stats_enabled=None as disabled if stats is missing
                if stats_enabled is None:
                    log_message("Node {} stats_enabled is None. Treating as stats not enabled.".format(node_id))
                    if _record_event(node_id, "stats_not_enabled"):
                        reason = "Stat reporting disabled or missing. Disconnecting and blocking node."
                        update_blocked_node(node_id, reason)
                        disconnect_node(node_id, args.initial_node_id, reason)
                        log_message("Blocked and disconnected node {}. Stopping further processing.".format(node_id))
                        return  # Stop further processing after blocking one node
                    log_message("Threshold not met for node {} stats-disabled event. Continuing monitoring.".format(node_id))
                    continue

                # Block and disconnect nodes explicitly reporting stats_enabled: False
                if stats_enabled is False:
                    log_message("Node {} stats_enabled is explicitly False.".format(node_id))
                    if _record_event(node_id, "stats_not_enabled"):
                        reason = "Stat reporting disabled. Disconnecting and blocking node."
                        update_blocked_node(node_id, reason)
                        disconnect_node(node_id, args.initial_node_id, reason)
                        log_message("Blocked and disconnected node {}. Stopping further processing.".format(node_id))
                        return  # Stop further processing after blocking one node
                    log_message("Threshold not met for node {} stats-disabled event. Continuing monitoring.".format(node_id))
                    continue

        else:
            log_message("No valid data retrieved for the initial node. Exiting.")
            break

        if args.loop:
            time.sleep(args.loop)
        else:
            break

if __name__ == "__main__":
    main()
