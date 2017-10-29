#!/usr/bin/env python2.7

import argparse, socket

parser = argparse.ArgumentParser()
parser.add_argument('--connections', help="Connections file")
parser.add_argument('--hosts', help="Hosts file")

args = parser.parse_args()

conn_labels = ["infection", "cnc", "other"]
host_labels = ["Benign", "Bot", "IsolatedInfection"]
legal_ports = range(1, 65535)


def is_legal_ipv4(s):
    try:
        socket.inet_aton(s)
    except Exception as e: 
        return False
    return True

def validate_connections(lines):
    splits = [line.split("|") for line in lines]
    index  = range(1, len(splits) + 1)
    splits = zip(splits, index)

    problems = {}

    problems['illegal_structures'] = [idx for split, idx in splits if len(split) != 7]
    problems['illegal_src_ips']    = [idx for split, idx in splits if not is_legal_ipv4(split[1])]
    problems['illegal_src_ports']  = [idx for split, idx in splits if not (split[2].isdigit() and int(split[2]) in legal_ports)]
    problems['illegal_dst_ips']    = [idx for split, idx in splits if not is_legal_ipv4(split[3])]
    problems['illegal_dst_ports']  = [idx for split, idx in splits if not (split[4].isdigit() and int(split[4]) in legal_ports)]
    problems['illegal_labels']     = [idx for split, idx in splits if not split[5] in conn_labels]

    for key, lines in problems.items():
        if len(lines) > 0:
            lines = lines[0:10]
            print("Detected {key} on lines {lines} and possibly more".format(**vars()))
    
    expected_conns = 30543
    num_uniques = len(set([frozenset(split[1:5]) for split, idx in splits]))

    if num_uniques < expected_conns:
        print("You only have {num_uniques} unique connection entries. Should have {expected_conns}.".format(**vars()))

def validate_hosts(lines):
    splits = [line.split("|") for line in lines]
    index  = range(1, len(splits) + 1)
    splits = zip(splits, index)

    problems = {}

    problems['illegal_structures'] = [idx for split, idx in splits if len(split) != 4]
    problems['illegal_host_ips']   = [idx for split, idx in splits if not is_legal_ipv4(split[1])]
    problems['illegal_labels']     = [idx for split, idx in splits if not split[2] in host_labels]

    for key, lines in problems.items():
        if len(lines) > 0:
            lines = lines[0:10]
            print("Detected {key} on lines {lines} and possibly more".format(**vars()))
    
    num_uniques = len(set([frozenset(split[1:2]) for split, idx in splits]))

    if num_uniques != len(splits):
        print("You appera to have duplicate host entries in your host file")

if args.connections is not None:
    print("\nValidating {args.connections}".format(**vars()))
    with open(args.connections) as f:
        validate_connections(f.readlines())
else:
    print("No connections file supplied for validation")

if args.hosts is not None:
    print("\nValidating {args.hosts}".format(**vars()))
    with open(args.hosts) as f:
        validate_hosts(f.readlines())
else:
    print("No hosts file supplied for validation")
