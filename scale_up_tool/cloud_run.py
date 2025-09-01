########################################################################################
# Copyright (C) 2021 Habana Labs, Ltd. an Intel Company                                #
# All Rights Reserved.                                                                 #
#                                                                                      #
# Unauthorized copying of this file or any element(s) within it, via any medium        #
# is strictly prohibited.                                                              #
# This file contains Habana Labs, Ltd. proprietary and confidential information        #
# and is subject to the confidentiality and license agreements under which it          #
# was provided.                                                                        #
#                                                                                      #
########################################################################################

"""
Cloud Run Module for Habana Performance Testing Tool.

This module provides functionality for running performance tests in cloud environments.
It includes progress tracking, connection management, and test coordination for both
external and internal testing scenarios.

Key Features:
- Progress tracking for distributed test execution
- Connection management for multiple host configurations
- Support for both external and internal network testing
- Thread-based progress monitoring
- Test result aggregation and reporting

Classes:
    None

Functions:
    getExternalProgressDict: Tracks progress for external network tests
    getInternalProgressDict: Tracks progress for internal network tests
    getConnections: Generates connection permutations for testing
    progress_task: Manages progress tracking in separate thread
    launchProgressThread: Launches progress monitoring thread
    external_testing: Coordinates external network performance tests
    internal_testing: Coordinates internal network performance tests
    main: Main entry point for cloud-based test execution
"""

import argparse
import json
import threading
import time
from tqdm import tqdm
from distributor import Distributor
from utils import (
    getPermutationsFullDuplex,
    getPermutations,
    initRemoteSSHSession,
    closeSSH,
    print_,
    executeCommandViaSSH,
    createDirectory
)
from common_args import add_common_args
import time
import copy

def getExternalProgressDict(get_host_connection, path2progress_prefix, pkey_path, known_hosts_file, dont_care):
    """
    Track progress for external network performance tests.

    This function monitors the progress of external network tests by checking
    for progress files on remote hosts via SSH connections.

    Args:
        get_host_connection (callable): Function that returns host connection information
        path2progress_prefix (str): Base path for progress files on remote hosts
        pkey_path (str): Path to the SSH private key file
        known_hosts_file (str): Path to the SSH known hosts file
        dont_care (str): Marker for connections to ignore during testing

    Returns:
        dict: Progress information keyed by server IP addresses

    Note:
        This function establishes SSH connections to monitor test progress
        and handles connection errors gracefully.
    """
    progress = {}

    for permutation in get_host_connection():
        client_permutation = permutation['client_permutation']
        finish = False
        while not finish:
            for index, server_list in enumerate(permutation['server_permutation']):
                clients = client_permutation[index].pop(0)
                for server, client in zip(server_list, clients):
                    if server == dont_care or client == dont_care:
                        continue
                    server_parts = server.strip().split(':')
                    server_ip = server_parts[0]
                    server_ssh_port = server_parts[1]
                    client_parts = client.strip().split(':')
                    client_ip = client_parts[0]
                    path = f'{path2progress_prefix}/{server_ip}_{client_ip}/scaleUpReport*'
                    if server_ip in progress.keys():
                        progress[server_ip]['pathes'].append(path)
                        progress[server_ip]['counter'].append(0)
                        progress[server_ip]['diff'].append(0)
                        progress[server_ip]['prev_counter'].append(0)
                    else:
                        progress[server_ip] = {
                            'pathes': [path],
                            'counter': [0],
                            'ssh': initRemoteSSHSession(f"{server_ip}:{server_ssh_port}", pkey_path, known_hosts_file),
                            'pbar': None,
                            'diff': [0],
                            'prev_counter': [0]
                        }
            if len(client_permutation[0]) == 0:
                finish = True
    return progress

def getInternalProgressDict(get_host_connection, path2progress_prefix, pkey_path, known_hosts_file, _):
    """
    Track progress for internal network performance tests.

    This function monitors the progress of internal network tests by checking
    for progress files on individual hosts.

    Args:
        get_host_connection (callable): Function that returns host connection information
        path2progress_prefix (str): Base path for progress files on remote hosts
        pkey_path (str): Path to the SSH private key file
        known_hosts_file (str): Path to the SSH known hosts file
        _ (any): Unused parameter for interface compatibility

    Returns:
        dict: Progress information keyed by host IP addresses

    Note:
        This function is specifically designed for internal network testing
        where tests run within individual hosts.
    """
    progress = {}
    for host in get_host_connection():
        host_parts = host.strip().split(':')
        host_ip = host_parts[0]
        host_ssh_port = host_parts[1]
        path = f'{path2progress_prefix}/{host_ip}/scaleUpReport*'
        progress[host_ip] = {
            'pathes': [path],
            'counter': [0],
            'ssh': initRemoteSSHSession(f"{host_ip}:{host_ssh_port}", pkey_path, known_hosts_file),
            'pbar': None,
            'diff': [0],
            'prev_counter': [0]
        }
    return progress

def getConnections(host_list, is_full_duplex_test, dont_care):
    """
    Generate connection permutations for performance testing.

    This function creates connection patterns between hosts based on the test type.
    For full duplex tests, it generates bidirectional connections, while for simplex
    tests, it generates unidirectional connections.

    Args:
        host_list (list): List of host IPs and ports in "ip:port" format
        is_full_duplex_test (bool): Flag indicating if the test is full duplex
        dont_care (any): Marker for connections to ignore during testing

    Returns:
        callable: Generator function that yields connection permutations

    Note:
        The returned generator yields dictionaries containing client and server
        permutation information for distributed testing.
    """
    ips = copy.deepcopy(host_list)
    if is_full_duplex_test:
        yield from getPermutationsFullDuplex(ips, dont_care)
    else:
        yield from getPermutations(ips, dont_care)

def progress_task(getProgressDict, get_host_connection, formatted_time, pkey_path, known_hosts_file, path_prefix ,stop_event, dont_care, title):
    """
    Track and update the progress of the tasks.

    Args:
        get_host_connection (function): Function to get host connections.
        pkey_path (str): Path to the SSH private key.
        path_prefix (str): Prefix for the progress path.
        stop_event (threading.Event): Event to signal stopping the task.
        dont_care (any): The mark to use for 'don't care' positions.
    """

    path2progress_prefix = path_prefix
    progress = {}

    def updateProgress(progress, info, i):
        if not progress.isdigit():
            return False
        prog_count = int(progress)
        if prog_count<1:
            return False
        info['prev_counter'][i] =  info['counter'][i]
        info['counter'][i] = prog_count
        info['diff'][i] = info['counter'][i] - info['prev_counter'][i]
        return True

    try:
        print(f"Initiate {title} test progress tracking")
        progress = getProgressDict(get_host_connection, path2progress_prefix, pkey_path, known_hosts_file, dont_care)
        has_meta_data = {}
        while  not stop_event.is_set():
            for ip, info in progress.items():
                if ip not in has_meta_data.keys():
                    has_meta_data[ip] = False
                if has_meta_data[ip]:
                    if info['pbar'].total <= info['pbar'].n:
                        continue
                    for i, path in enumerate(info['pathes']):
                        try:
                            prog = executeCommandViaSSH(info['ssh'], f'cat {path} | egrep ", Server|ERROR|FAILED|UNKNOWN|TIMEOUT|PASSED" | grep -v "*" -c')[0].strip()
                        except Exception:
                            continue
                        if not updateProgress(prog, info, i):
                            continue
                    for diff in info['diff']:
                        if diff >0:
                            info['pbar'].update(diff)
                else:
                    try:
                        path = info['pathes'][0]
                        meta_data = executeCommandViaSSH(info['ssh'], f'cat /tmp/perftest_metadata{formatted_time}.json')[0].strip()
                        meta_data = json.loads(meta_data)
                        has_meta_data[ip] = True
                    except Exception:
                        continue
                    info['pbar'] =  tqdm(total= meta_data["total_iterations"] *len(info['pathes']))
                    info['pbar'].set_description(f"{ip} ({title} test)")

    finally:
        for info in progress.values():
            if info['pbar'].total <= info['pbar'].n:
                info['pbar'].close()
                executeCommandViaSSH(info['ssh'], f'rm /tmp/perftest_metadata{formatted_time}.json')
                closeSSH(info['ssh'])
                continue
            for i, path in enumerate(info['pathes']):
                try:
                    prog = executeCommandViaSSH(info['ssh'], f'cat {path} | egrep ", Server|ERROR|FAILED|UNKNOWN|TIMEOUT|PASSED" | grep -v "*" -c')[0].strip()
                except Exception:
                    continue
                if not updateProgress(prog, info, i):
                    continue

            for diff in info['diff']:
                if diff >0:
                    info['pbar'].update(diff)

            executeCommandViaSSH(info['ssh'], f'rm /tmp/perftest_metadata{formatted_time}.json')
            closeSSH(info['ssh'])
            info['pbar'].close()

def launchProgressThread(getProgressDict, get_host_connection, formmated_time, pkey_path, known_hosts_file, path_prefix ,stop_event, dont_care, title):
    """
    Launch the progress thread.

    Args:
        get_host_connection (function): Function to get host connections.
        pkey_path (str): Path to the SSH private key.
        path_prefix (str): Prefix for the progress path.
        stop_event (threading.Event): Event to signal stopping the task.
        dont_care (any): The mark to use for 'don't care' positions.
    """
    progress_thread = threading.Thread(target=progress_task, args=(getProgressDict, get_host_connection, formmated_time, pkey_path, known_hosts_file, path_prefix ,stop_event, dont_care, title))
    progress_thread.start()
    return progress_thread

def external_testing(args, hosts, report_name, formmated_time):
    print_(f"\nExternal nics test", report_name)
    print_(f"------------------\n", report_name)
    force_stop = False
    #create pairs list (server, client)
    dont_care = 'DoNtCaRe'
    get_host_connection = lambda : getConnections(hosts, args.test_type != 'ping_pong', dont_care)
    error_counter  =0
    stop = threading.Event()
    progress_thread = launchProgressThread(getExternalProgressDict ,get_host_connection, formmated_time, args.ssh_key_file, args.known_hosts_file, f'{args.output}' ,stop, dont_care, 'external')
    try:
        args.time_stampe = formmated_time
        #create disributor
        dist = Distributor(args)
        start = time.perf_counter()
        for permutation in get_host_connection():
            client_permutation = permutation['client_permutation']
            finish = False
            while not finish:
                 for index, server_list in enumerate(permutation['server_permutation']):
                    clients = client_permutation[index].pop(0)
                    for server, client in zip(server_list, clients):
                        if server == dont_care or client == dont_care:
                           continue
                        dist.apply(server, client)
                 error_counter += len(dist.sync(report_name))
                 if len(client_permutation[0]) == 0:
                     finish = True
    except KeyboardInterrupt:
        dist.signal_stop()
        force_stop = True
    finally:
        error_counter += len(dist.sync(report_name))
        end = time.perf_counter()
        stop.set()
        progress_thread.join()
        if force_stop:
            print_(f"The script stoped by the user", report_name)
        if not force_stop and error_counter == 0:
            print_(f"All tests completed :)", report_name)
        print_(f'Duration: {((end - start)/60):.3f} minuets', report_name)

def internal_testing(args, hosts, report_name, formmated_time):
    title = ''
    if args.test_local:
        title = 'local external'
        print_(f"\nExternal nics local test", report_name)
    else:
        title = 'internal'
        print_(f"\nInternal nics test", report_name)
    print_(f"------------------\n", report_name)

    force_stop = False
    error_counter  =0
    stop = threading.Event()
    progress_thread = launchProgressThread( getInternalProgressDict, lambda: (ip for ip in hosts) , formmated_time, args.ssh_key_file, args.known_hosts_file, f'{args.output}' ,stop, 'DoNtCaRe', title)
    try:
        args.time_stampe = formmated_time
        dist = Distributor(args)
        start = time.perf_counter()
        for server in hosts:
            dist.apply(server)
        error_counter += len(dist.sync(report_name))
    except KeyboardInterrupt:
        dist.signal_stop()
        force_stop = True
    finally:
        error_counter += len(dist.sync(report_name))
        end = time.perf_counter()
        stop.set()
        progress_thread.join()
        if force_stop:
            print_(f"The script stoped by the user", report_name)
        if not force_stop and error_counter == 0:
            print_(f"All tests completed :)", report_name)
        print_(f'Duration: {((end - start)/60):.3f} minuets', report_name)


def main(args):
    """
    Main function to execute the cloud tool.

    Args:
        args (argparse.Namespace): Parsed command-line arguments.
    """
    print('########################################################################################')
    print('#                                Cloud Testing Tool                                    #')
    print('########################################################################################')
    current_time = time.localtime()
    formatted_time = time.strftime("%Y-%m-%d::%H:%M:%S", current_time)

    if len(args.output) != 0:
        output_dir = f"{args.output}/{args.test_type}_{formatted_time}"
    else:
        output_dir = f'./{args.test_type}_{formatted_time}'
    args.output = output_dir
    createDirectory(args.output)
    report_name = f"{args.output}/CloudReport_{formatted_time}.txt"
    with open(report_name, 'w') as file:
        pass
    #take file with IPs and command as input
    hosts = None
    with open(args.host_file, 'r') as file:
        # Read all lines into a list and strip newline characters
        hosts = [line.strip() for line in  file]
    if hosts == None:
        raise BaseException(f"ERROR:: Can't open hostfile: {args.host_file}")
    if not args.disable_remote_external_test:
        if len(hosts) < 2:
            raise BaseException(f"ERROR:: IPs count < 2 : {args.host_file}")
        external_testing(args, hosts, report_name, formatted_time)
    if args.internal or args.test_local:
        internal_testing(args, hosts, report_name, formatted_time)

    with open(report_name, 'r') as file:
        # Read the file content
        content = file.read()
        # Print the content to stdout
        print(f'{content}', flush=True)

if __name__ == '__main__':
    """
    Entry point for the script. Parses command-line arguments and calls the main function.
    """
    parser = argparse.ArgumentParser(prog='Cloud Testing Tool')
    parser.add_argument('-hf', '--host_file', metavar='', type=str, required=True, help="path to a host_file that include a host IP list")

    add_common_args(parser)

    args= parser.parse_args()
    if args.internal and args.test_type == 'write_lat':
        raise BaseException(f"ERROR:: Latency test is not supported for internal NIC")

    main(args)



