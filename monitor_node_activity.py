#!/usr/bin/python3

import argparse
import collections
import logging
import os
import re
import subprocess
import time

LOG_FILE = "/var/log/asterisk/node_activity_monitor.log"
logging.basicConfig(filename=LOG_FILE, level=logging.DEBUG, format="%(asctime)s - %(message)s")

SUDO = "/usr/bin/sudo"
ASTERISK = "/usr/sbin/asterisk"
DB_FAMILY = "blacklist"

DEFAULT_EVENT_PATTERNS = [
    r"\bquick\s*key\b",
    r"\bkeyed\s*up\b",
    r"\bburst\b",
    r"\binterference\b",
    r"\bnoise\b",
]

DEFAULT_NODE_REGEX = r"node(?:\s+id)?[:=]\s*(?P<node>\d+)"


def log_message(message):
    logging.debug(message)
    print(message)


def update_blocked_node(node_id, comment=""):
    sanitized_comment = comment.replace(" ", "_")
    command = '{} {} -rx "database put {} {} {}"'.format(
        SUDO, ASTERISK, DB_FAMILY, node_id, sanitized_comment
    )
    log_message("Running command: {}".format(command))
    subprocess.run(command, shell=True, check=True)
    log_message("Blocked node {} with comment: {}".format(node_id, sanitized_comment))


def disconnect_node(node_id, initial_node_id, reason=""):
    command = '{} {} -rx "rpt fun {} *1{}"'.format(SUDO, ASTERISK, initial_node_id, node_id)
    log_message("Disconnecting node {} from {}. Reason: {}".format(node_id, initial_node_id, reason))
    subprocess.run(command, shell=True, check=True)
    log_message("Node {} disconnected from {} successfully.".format(node_id, initial_node_id))


def compile_event_patterns(patterns):
    return [re.compile(pattern, re.IGNORECASE) for pattern in patterns]


def compile_node_regex(pattern):
    return re.compile(pattern, re.IGNORECASE)


def iter_log_lines(log_path, poll_interval=0.5):
    with open(log_path, "r") as log_file:
        log_file.seek(0, os.SEEK_END)
        while True:
            line = log_file.readline()
            if line:
                yield line
            else:
                time.sleep(poll_interval)


def parse_node_id(line, node_regex):
    match = node_regex.search(line)
    if not match:
        return None
    return match.group("node")


def matches_event(line, event_patterns):
    return any(pattern.search(line) for pattern in event_patterns)


def prune_old_events(events, cutoff):
    while events and events[0] < cutoff:
        events.popleft()


def handle_violation(node_id, state, now, args):
    violations = state["violations"]
    violations.append(now)
    prune_old_events(violations, now - args.window_seconds)

    if not state["disconnected"] and len(violations) >= args.disconnect_threshold:
        reason = "Disconnecting: repeated keying/noise/interference events."
        try:
            disconnect_node(node_id, args.initial_node_id, reason)
        except subprocess.CalledProcessError as exc:
            log_message("Failed to disconnect node {}: {}".format(node_id, exc))
        state["disconnected"] = True
        state["post_disconnect_violations"] = 0
        state["last_disconnect"] = now
        return

    if state["disconnected"]:
        state["post_disconnect_violations"] += 1
        if state["post_disconnect_violations"] >= args.block_threshold:
            reason = "Blocking: continued keying/noise/interference after disconnect."
            try:
                update_blocked_node(node_id, reason)
            except subprocess.CalledProcessError as exc:
                log_message("Failed to block node {}: {}".format(node_id, exc))
            state["post_disconnect_violations"] = 0


def monitor(args):
    event_patterns = compile_event_patterns(args.event_pattern)
    node_regex = compile_node_regex(args.node_regex)
    node_state = collections.defaultdict(
        lambda: {
            "violations": collections.deque(),
            "disconnected": False,
            "post_disconnect_violations": 0,
            "last_disconnect": None,
        }
    )

    for line in iter_log_lines(args.log_file, args.poll_interval):
        if not matches_event(line, event_patterns):
            continue

        node_id = parse_node_id(line, node_regex)
        if not node_id:
            log_message("Matched event without node ID: {}".format(line.strip()))
            continue

        log_message("Detected event for node {}: {}".format(node_id, line.strip()))
        handle_violation(node_id, node_state[node_id], time.time(), args)


def build_parser():
    parser = argparse.ArgumentParser(
        description="Monitor Asterisk logs and disconnect/block nodes with rapid keying or noise bursts."
    )
    parser.add_argument(
        "--initial-node-id",
        required=True,
        help="The local node ID used to disconnect remote nodes via rpt.",
    )
    parser.add_argument(
        "--log-file",
        default="/var/log/asterisk/messages",
        help="Path to the Asterisk log file to monitor.",
    )
    parser.add_argument(
        "--event-pattern",
        action="append",
        default=[],
        help="Regex pattern to detect quick-keying or interference events. Can be repeated.",
    )
    parser.add_argument(
        "--node-regex",
        default=DEFAULT_NODE_REGEX,
        help="Regex with a named 'node' group to extract node IDs.",
    )
    parser.add_argument(
        "--window-seconds",
        type=int,
        default=60,
        help="Time window to count events before disconnecting.",
    )
    parser.add_argument(
        "--disconnect-threshold",
        type=int,
        default=3,
        help="Number of events within the window required to disconnect.",
    )
    parser.add_argument(
        "--block-threshold",
        type=int,
        default=2,
        help="Number of events after a disconnect required to block the node.",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=0.5,
        help="Polling interval in seconds when waiting for new log lines.",
    )
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.event_pattern:
        args.event_pattern = DEFAULT_EVENT_PATTERNS[:]

    log_message("Starting node activity monitor with log file: {}".format(args.log_file))
    log_message("Event patterns: {}".format(args.event_pattern))
    monitor(args)


if __name__ == "__main__":
    main()
