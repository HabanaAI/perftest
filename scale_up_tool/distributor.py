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
Distributor Module for Habana Performance Testing Tool.

This module provides distributed task execution capabilities for performance testing
across multiple hosts. It manages test distribution, execution coordination, and
result collection in parallel processing environments.

Key Features:
- Distributed test execution across multiple hosts
- Parallel processing with multiprocessing support
- SSH-based remote command execution
- Automatic artifact collection and management
- IP address resolution and network connectivity
- Task queue management and synchronization

Classes:
    Distributor: Abstract base class for distributed test execution

Functions:
    get_ip: Determines the local machine's IP address
    get_ip_from_hostname: Resolves IP address from hostname
    copy_artifacts: Copies test artifacts from remote hosts
    task: Executes individual test tasks on remote hosts
"""

from abc import ABC
import multiprocessing
import queue
import os
import re
import shutil
import socket
import time
import paramiko
from utils import (
    executeCommandViaSSHAndRedirect,
    initRemoteSSHSession,
    closeSSH,
    sftp_recursive_get,
    createDirectory,
    executeSubProc,
    executeCommandViaSSH,
    print_,
    MyRotatingFile,
    set_non_interactive_shell,
    recover_interactive_shell
)

def get_ip():
    """
    Determine the local machine's IP address using multiple methods.

    This function attempts to find the local machine's IP address by trying
    different approaches in order of reliability:
    1. Connect to external DNS server to determine outbound IP
    2. Parse system routing table for default route source IP
    3. Fall back to localhost if all methods fail

    Returns:
        str: The local machine's IP address, or '127.0.0.1' if detection fails

    Note:
        This function prioritizes non-localhost addresses and handles various
        network configuration scenarios gracefully.
    """
    # Method 1: Try connecting to an external DNS server
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            if ip and not ip.startswith('127.'):
                return ip
    except (socket.error, OSError):
        pass

    # Method 2: Try system routing table
    try:
        import subprocess
        result = subprocess.run(['ip', 'route', 'get', '1.1.1.1'],
                              capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if 'src' in line:
                    ip = line.split('src')[1].strip().split()[0]
                    if ip and not ip.startswith('127.'):
                        return ip
    except (subprocess.SubprocessError, FileNotFoundError, subprocess.TimeoutExpired, ImportError):
        pass

    return '127.0.0.1'

def get_ip_from_hostname(hostname):
    """
    Resolve a hostname to an IP address with validation.

    This function resolves a hostname to its corresponding IP address. If the
    input is already an IP address, it returns it unchanged. The function
    includes validation to ensure the resolved IP is not a loopback address.

    Args:
        hostname (str): The hostname to resolve or IP address to validate

    Returns:
        str: The resolved IP address, or None if resolution fails

    Note:
        - IPv4 addresses are returned as-is if they match the pattern
        - Loopback addresses (127.x.x.x) are rejected unless from localhost
        - Network resolution errors are handled gracefully
    """
    ipv4_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    # Check if the hostname is already an IPv4 address
    if ipv4_pattern.match(hostname):
        return hostname
    # The hostname is not an IP address, so we try to resolve it
    try:
        current_hostname = socket.gethostname()
        resolved_ip = socket.gethostbyname(hostname)
        import ipaddress
        try:
            ip_obj = ipaddress.IPv4Address(resolved_ip)
            # If the resolved IP is a loopback address and matches the current hostname, return the current external IP
            if ip_obj.is_loopback and (hostname == current_hostname or hostname.split('.')[0] == current_hostname.split('.')[0]):
                return get_ip()
            return resolved_ip
        except ipaddress.AddressValueError:
            return resolved_ip

    except socket.gaierror:
        pass

    return hostname

def copy_artifacts(ssh_ssesion, server_name, server_ip, client_name, output_artifacts_path, output_path):
    """
    Copy test artifacts from remote server to local machine via SSH.

    This function retrieves test result files and artifacts from a remote server
    using SFTP over SSH. It handles both server-only and client-server test scenarios,
    organizing the copied files in appropriate directory structures.

    Args:
        ssh_ssesion: Active SSH session object for the remote connection
        server_name (str): Name identifier for the server host
        server_ip (str): IP address of the server host
        client_name (str): Name identifier for the client host (None for server-only tests)
        output_artifacts_path (str): Remote path where artifacts are located
        output_path (str): Local base directory to store copied artifacts

    Note:
        - Creates local directory structure based on server/client naming
        - Handles both single-host and multi-host test artifact collection
        - Uses recursive SFTP transfer for complete directory copying
    """
    root_path = '.'
    if len(output_path) != 0:
        root_path = output_path
    if client_name != None:
        source = f'/tmp/scale_up_console_{server_name}_{client_name}.txt'
    else:
        source = f'/tmp/scale_up_console_{server_name}.txt'
    if client_name != None:
        createDirectory(f'{root_path}/{server_name}_{client_name}')## manager end (can be server end)
    else:
        createDirectory(f'{root_path}/{server_name}')
    if client_name != None:
        path_ = f'{root_path}/{server_name}_{client_name}'
    else:
        path_ = f'{root_path}/{server_name}'
    try:
        shutil.copy(source, path_)
    except Exception as e:
        print(f"An error occurred: {e}")
    try:
        os.remove(source)
    except Exception as e:
        print(f"An error occurred: {e}")
    try:
        sftp = None
        current_external_ip = get_ip()
        current_end_name = socket.gethostname()
        current_internal_ip = get_ip_from_hostname(current_end_name)
        if server_ip != current_external_ip and server_ip != current_internal_ip: #manager is not a tested server
            sftp = ssh_ssesion.open_sftp()
            sftp_recursive_get(sftp, output_artifacts_path, path_ )
            remote_path_to_remove = '/'.join(output_artifacts_path.split('/')[:-1])
            _ = executeCommandViaSSH(ssh_ssesion, f'rm -rf {remote_path_to_remove}')
    except Exception as e:
        print(f"An error occurred during sftp: {e}")
        paramiko.util.log_to_file("/tmp/paramiko.log")
    finally:
        if server_ip != current_external_ip and server_ip != current_internal_ip: #manager is not a tested server
            if sftp != None:
                sftp.close()

def task(ssh_args, pre_commands, ssh_command, server_name, server_ip, client_name, output_artifacts_path, output_path, q):
    """
    Execute a distributed test task on a remote server via SSH.

    This function manages the complete lifecycle of a remote test execution,
    including SSH session establishment, command execution, output handling,
    and artifact collection. It supports both preparation commands and main
    test execution with comprehensive error handling.

    Args:
        ssh_args (str): SSH connection string in "ip:port" format
        pre_commands (list): List of preparation commands to execute first
        ssh_command (str): Main test command to execute on remote host
        server_name (str): Identifier name for the server host
        server_ip (str): IP address of the server host
        client_name (str): Identifier name for the client host (None for single-host)
        output_artifacts_path (str): Remote path containing test result artifacts
        output_path (str): Local directory to store copied artifacts
        q (multiprocessing.Queue): Queue for returning execution results and output

    Note:
        - Establishes SSH session with proper error handling
        - Executes preparation commands before main test
        - Collects and returns both stdout and stderr output
        - Automatically copies test artifacts upon completion
        - Places results in multiprocessing queue for parent process retrieval
    """
    file = None
    ssh_session = None
    try:
        set_non_interactive_shell(*ssh_args)
        ssh_session = initRemoteSSHSession(*ssh_args)

        for cmd in pre_commands:
            _ = executeCommandViaSSH(ssh_session, cmd)
        if client_name != None:
            file_name = f'/tmp/scale_up_console_{server_name}_{client_name}.txt'
        else:
            file_name = f'/tmp/scale_up_console_{server_name}.txt'
        file = MyRotatingFile(file_name)
        return_code, lines = executeCommandViaSSHAndRedirect(ssh_session, ssh_command, f'[server_name:: {server_name}] ', file, 10*60)
        q.put((return_code, lines))
    except Exception as e:
        print(f"An error occurred during task execution: {e}")
        q.put((None, None))
    finally:
        if file != None:
            file.close()
        if ssh_session != None:
            try:
                copy_artifacts(ssh_session, server_name, server_ip, client_name, output_artifacts_path, output_path)
            except Exception as e:
                print(f"An error occurred during artifact copy: {e}")
            recover_interactive_shell(*ssh_args)
            closeSSH(ssh_session)


class Distributor(ABC):
    """
    Abstract base class for distributed performance test execution.

    This class provides the framework for distributing and managing performance tests
    across multiple remote hosts. It handles process management, result synchronization,
    and error collection in a multiprocessing environment.

    Key Features:
    - Parallel test execution across multiple hosts
    - Process lifecycle management (start, monitor, cleanup)
    - Result synchronization and error collection
    - SSH-based remote execution coordination
    - Graceful shutdown handling

    Attributes:
        __ipc (list): List of active multiprocessing contexts
        __processes (list): List of running subprocess instances
        __result_queue (Queue): Queue for collecting test results
        __args: Configuration arguments for test execution

    Abstract Methods:
        Subclasses must implement specific test execution logic.
    """
    def __init__(self, args) -> None:
        """
        Initialize the Distributor with configuration arguments.

        Sets up the multiprocessing infrastructure, result collection queues,
        and configuration parameters needed for distributed test execution.

        Args:
            args: Configuration object containing test parameters, SSH settings,
                 output paths, and other execution options
        """
        super().__init__()
        self.__ipc = []
        self.__args = args
        self.__output_path = args.output

    def apply(self, server, client= None):
        """
        Applies a task to a server-client pair.

        Args:
            server: The server address in the format 'ip:port'.
            client: The client address in the format 'ip:port'.
        """
        server_parts = server.strip().split(':')
        server_name = server_parts[0]
        server_ssh_port = server_parts[1]
        if client != None:
            client_parts = client.strip().split(':')
            client_name = client_parts[0]
            client_port = client_parts[1]
        else:
            client_name = None
            client_port = None

        server_ip = get_ip_from_hostname(server_name)
        if client != None:
            client_ip = get_ip_from_hostname(client_name)
        if server_ip != server_name:
            server_ip_and_name = f'{server_ip}(&&{server_name}&&)'
        else:
            server_ip_and_name = server_name
        if client != None and client_ip != client_name:
            client_ip_and_name = f'{client_ip}(&&{client_name}&&)'
        elif client != None:
            client_ip_and_name = client_name

        scrtip_path = executeSubProc('pwd')[0] ## manager end (maybe server end)
        output_artifacts_path = ""

        ssh_command = f"cd {scrtip_path} && python3 ./run.py "
        pre_commands = []
        if client != None:
            output_artifacts_path = f'{self.__output_path}/{server_name}_{client_name}'
        else:
            output_artifacts_path = f'{self.__output_path}/{server_name}'
        ssh_command   += f'--output "{output_artifacts_path}" '
        pre_commands.append(f'mkdir -p {output_artifacts_path}')

        ssh_command += f'--ssh_key_file "{self.__args.ssh_key_file}" '
        ssh_command += f'--known_hosts_file "{self.__args.known_hosts_file}" '
        ssh_command += f'--server_hostname "{server_ip_and_name}" '
        ssh_command += f'--time_stampe "{self.__args.time_stampe}" '
        if client != None:
            ssh_command += f'--client_hostname "{client_ip_and_name}" --ssh_port {client_port} '
        ssh_command += f"perftest "

        if self.__args.test_local:
            ssh_command += "--test_local "
        elif client == None:
            ssh_command += "--internal "
        if self.__args.basic_check:
            ssh_command += "--basic_check "


        ssh_command += f"{self.__args.test_type} "
        ssh_command += f"--rx_depth {self.__args.rx_depth} "
        ssh_command += f"--size {self.__args.size} "
        ssh_command += f"--iters {self.__args.iters} "
        if hasattr(self.__args, 'chk') and self.__args.chk:
            ssh_command += f"--chk "
        if hasattr(self.__args, 'criteria') and self.__args.criteria > 0:
            ssh_command += f"--criteria {self.__args.criteria} "

        ssh_command = ssh_command.rstrip()

        ssh_args = (f"{server_name}:{server_ssh_port}", self.__args.ssh_key_file, self.__args.known_hosts_file)
        q = multiprocessing.Queue()
        p = multiprocessing.Process(target=task, args=(ssh_args, pre_commands, ssh_command, server_name, server_ip, client_name, output_artifacts_path, self.__output_path, q))

        self.__ipc.append((p, q, server_name, client_name))
        p.start()

    def signal_stop(self):
        """
        Signals all running processes to stop.
        """
        for p, _, _,_  in self.__ipc:
            p.terminate()

    def sync(self, report_name):
        """
        Waits for all processes to complete and collects their return codes.

        Args:
            report_name: The name of the report file.

        Returns:
            A list of return codes from the processes.
        """
        return_codes = []
        return_code = None
        for p, q, server_name, client_name   in self.__ipc:
            while q.empty() and p.is_alive():
                time.sleep(0.25)
            if not q.empty():
                return_code, _ = q.get()
            if return_code == None:
                if client_name != None:
                    print_(f"{server_name} -> {client_name} : FAILED (255)", report_name)
                else:
                    print_(f"{server_name} : FAILED (255)", report_name)
                return_codes.append(255)
            elif return_code != 0:
              if client_name != None:
                print_(f"{server_name} -> {client_name} : FAILED ({return_code})", report_name)
              else:
                print_(f"{server_name} : FAILED ({return_code})", report_name)
              print_(self.__get_test_summary(server_name, client_name), report_name)
              return_codes.append((return_code))

            p.join(timeout=30*60)
            if p.is_alive():
               p.terminate()
               p.join()
               if client_name != None:
                   print_(f"{server_name} -> {client_name} : TIMEOUT (300)", report_name)
               else:
                    print_(f"{server_name} : UNKNOWN (300)", report_name)
               return_codes.append(300)
        self.__ipc.clear()

        return return_codes

    def __get_test_summary(self, server_ip, client_ip):
        """
        Retrieves the test summary from the output files.

        Args:
            server_ip: The IP address of the server.
            client_ip: The IP address of the client.

        Returns:
            A string containing the test summary.
        """
        prefix_name = 'scale_up_console_'
        if client_ip != None:
            path_ = f'{self.__output_path}/{server_ip}_{client_ip}'
        else:
            path_ = f'{self.__output_path}/{server_ip}'
        report_path = None
        for filename in os.listdir(path_):
            file_path = os.path.join(path_, filename)
            if prefix_name in file_path and  os.path.isfile(file_path):
                report_path = file_path
                break

        if report_path == None:
            return ''

        with open(report_path, 'r') as report:
            lines = report.readlines()

        index = -1
        original_index = None
        for i, line in enumerate(lines):
            original_index =  i
            if '*      Summary       *' in line:
                index = original_index
                break
        if original_index == None:
            if client_ip != None:
                return 'Timeout - exceed 2 boxes limit - 10 minutes\n'
            else:
                return 'Timeout - exceed 1 box limit - 10 minutes\n'
        return '\n'.join(lines[index+1:])

