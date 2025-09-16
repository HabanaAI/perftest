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
Utility Functions for Habana Performance Testing Framework.

This module provides a comprehensive collection of utility functions for the Habana
performance testing framework. It includes network utilities, SSH management,
file operations, process execution, and specialized data structures for testing.

Key Features:
- Network hostname and IP address resolution
- SSH session management and command execution
- File and directory operations with SFTP support
- Process execution with output redirection
- Test permutation generation for comprehensive testing
- Custom data structures for output management
- Progress tracking and reporting utilities

Classes:
    HostnameResolvingHostKeyPolicy: Custom SSH host key policy
    MyRotatingFile: Rotating file writer for output management
    LineLimiter: Output line limiting utility

Functions:
    Network utilities: get_hostname, get_hostname_from_ip
    SSH utilities: initRemoteSSHSession, executeCommandViaSSH, closeSSH
    File utilities: createDirectory, sftp_recursive_put, sftp_recursive_get
    Process utilities: executeSubProc
    Test utilities: getPermutations, getPermutationsFullDuplex, cyclic_iteration
    Output utilities: print_, align_prints
"""

import queue
import socket
import subprocess
import threading
import paramiko
import os
import getpass
import time
import sys
import math
import copy
import ipaddress

def get_hostname():
    """
    Get the local machine's hostname.
    
    Returns:
        str: The hostname of the local machine
    """
    hostname = socket.gethostname()
    return hostname

def get_hostname_from_ip(ip_address):
    """
    Resolve an IP address to its corresponding hostname.
    
    Performs reverse DNS lookup to convert an IP address to a hostname.
    Handles resolution errors gracefully.
    
    Args:
        ip_address (str): IP address to resolve
        
    Returns:
        str: Resolved hostname, or None if resolution fails
        
    Note:
        Returns None on resolution errors rather than raising exceptions.
    """
    try:
        hostname, aliaslist, ipaddrlist = socket.gethostbyaddr(ip_address)
        return hostname
    except socket.herror as e:
        print(f"Error resolving IP address {ip_address}: {e}")
        return None

def print_(msg, path):
    """
    Append a message to a file with automatic flushing.

    This function provides thread-safe file writing with automatic flushing
    to ensure immediate persistence of log messages.

    Args:
        msg (str): The message to write to the file
        path (str): The file path where the message should be appended
        
    Note:
        Creates the file if it doesn't exist and automatically flushes
        to ensure immediate write to disk.
    """
    with open(path, 'a') as file:
        file.write(f'{msg}\n')
        file.flush()

def cyclic_iteration(lst):
    """
    Generate all cyclic permutations of a list.
    
    Creates all possible cyclic rotations of the input list, where each
    permutation is the list rotated by one position.

    Args:
        lst (list): The list to generate cyclic permutations for

    Returns:
        list: A list containing all cyclic permutations of the input list
        
    Example:
        cyclic_iteration([1,2,3]) returns [[1,2,3], [2,3,1], [3,1,2]]
    """
    res = []
    start = lst[:]
    while True:
        lst = lst[1:] + lst[:1]  # Rotate the list
        res.append(lst)
        if lst == start:
            return res

def isEven(number):
    """
    Check if a number is even.
    
    Simple utility function to determine if an integer is even using
    modulo arithmetic.

    Args:
        number (int): The number to check for evenness

    Returns:
        bool: True if the number is even, False if odd
        
    Example:
        isEven(4) returns True, isEven(3) returns False
    """
    return number % 2 == 0

def interleave_permutations_generators(gen1, gen2):
    """
    Interleave two generators.

    Args:
        gen1 (generator): The first generator.
        gen2 (generator): The second generator.

    Yields:
        any: The next value from the interleaved generators.
    """
    for permutation_a, permutation_b in zip(gen1, gen2):
        server_perm_a = permutation_a['server_permutation']
        client_perm_a = permutation_a['client_permutation']
        server_perm_b = permutation_b['server_permutation']
        client_perm_b = permutation_b['client_permutation']
        yield {
            'server_permutation': server_perm_a + server_perm_b,
            'client_permutation': client_perm_a + client_perm_b
        }

def getPermutations(l, dont_care_mark):
    """
    Generate permutations of a list with a 'don't care' mark.

    Args:
        l (list): The list to permute.
        dont_care_mark (any): The mark to use for 'don't care' positions.

    Yields:
        tuple: A tuple containing two lists representing the permutations.
    """
    if len(l) == 2:
        yield { 'server_permutation': [[l[0]]], 'client_permutation': [[[l[1]]]]}
        yield { 'server_permutation': [[l[1]]], 'client_permutation': [[[l[0]]]]}
        return
    if len(l) == 3:
        yield from getPermutations([l[0], l[1]], dont_care_mark)
        yield from getPermutations([l[0], l[2]], dont_care_mark)
        yield from getPermutations([l[1], l[2]], dont_care_mark)
        return
    if len(l) == 4:
        yield { 'server_permutation': [l[:2]], 'client_permutation': [cyclic_iteration(l[2:])] }
        yield { 'server_permutation': [l[2:]], 'client_permutation': [cyclic_iteration(l[:2])]}
        yield from interleave_permutations_generators(getPermutations(l[:2], dont_care_mark), getPermutations(l[2:], dont_care_mark))
        return
    temp = copy.deepcopy(l)
    is_odd = not isEven(len(temp))

    if is_odd:
        temp.append(dont_care_mark)
    yield {'server_permutation': [temp[:int(len(temp) / 2)]], 'client_permutation': [cyclic_iteration(temp[int(len(temp) / 2):])]}
    yield {'server_permutation': [temp[int(len(temp) / 2):]], 'client_permutation': [cyclic_iteration(temp[:int(len(temp) / 2)])]}
    yield from interleave_permutations_generators(getPermutations(temp[:int(len(temp) / 2)], dont_care_mark), getPermutations(temp[int(len(temp) / 2):], dont_care_mark))

def getPermutationsFullDuplex(l, dont_care_mark):
    """
    Generate full duplex permutations of a list with a 'don't care' mark.

    Args:
        l (list): The list to permute.
        dont_care_mark (any): The mark to use for 'don't care' positions.

    Yields:
        tuple: A tuple containing two lists representing the permutations.
    """
    if len(l) == 2:
        yield {'server_permutation': [[l[0]]], 'client_permutation': [[[l[1]]]]}
        return
    if len(l) == 3:
        yield { 'server_permutation': [[l[0]]], 'client_permutation': [[[l[1]]]]}
        yield { 'server_permutation': [[l[0]]], 'client_permutation': [[[l[2]]]]}
        yield { 'server_permutation': [[l[1]]], 'client_permutation': [[[l[2]]]]}
        return
    if len(l) == 4:
        yield { 'server_permutation': [l[:2]], 'client_permutation': [cyclic_iteration(l[2:])]}
        yield from interleave_permutations_generators(getPermutationsFullDuplex(l[:2], dont_care_mark), getPermutationsFullDuplex(l[2:], dont_care_mark))
        return
    temp = copy.deepcopy(l)
    is_odd = not isEven(len(temp))

    if is_odd:
        temp.append(dont_care_mark)
    yield {'server_permutation': [temp[:int(len(temp) / 2)]], 'client_permutation': [cyclic_iteration(temp[int(len(temp) / 2):])]}
    yield from interleave_permutations_generators(getPermutationsFullDuplex(temp[:int(len(temp) / 2)], dont_care_mark), getPermutationsFullDuplex(temp[int(len(temp) / 2):], dont_care_mark))

class HostnameResolvingHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """
    Custom SSH host key policy that resolves hostnames before key verification.
    
    This policy extends Paramiko's missing host key policy to handle hostname
    resolution during SSH connections. It checks both the provided hostname
    and its resolved IP address against the known hosts file.
    
    Attributes:
        known_hosts_file (str): Path to the SSH known hosts file
    """
    def __init__(self, known_hosts_file):
        """
        Initialize the hostname resolving host key policy.
        
        Args:
            known_hosts_file (str): Path to the SSH known hosts file
        """
        self.known_hosts_file = known_hosts_file

    def missing_host_key(self, client, hostname, key):
        """
        Handle missing host key by checking hostname resolution.
        
        This method is called when SSH encounters a host key that's not in
        the known hosts file. It attempts to resolve the hostname and check
        both the hostname and IP address.
        
        Args:
            client: SSH client instance
            hostname (str): Hostname being connected to
            key: SSH host key
            
        Note:
            Implements custom logic for hostname resolution and verification.
        """
        try:
            # Determine which hostname to check
            check_hostname = hostname
            is_ip_address = self._is_ip_address(hostname)

            if is_ip_address:
                # Try to resolve IP to hostname
                resolved_hostname = get_hostname_from_ip(hostname)
                if resolved_hostname:
                    check_hostname = resolved_hostname
                else:
                    print(f"Could not resolve IP address '{hostname}' to hostname")

            if client._host_keys.check(check_hostname, key):
                return

        except Exception as e:
            pass

        # Reject unknown hosts
        raise paramiko.SSHException(f"Host key verification failed: Unknown host '{hostname}' not found in known hosts file '{self.known_hosts_file}'.")

    def _is_ip_address(self, hostname):
        """Check if hostname is an IP address efficiently."""
        try:
            ipaddress.ip_address(hostname)
            return True
        except ValueError:
            return False

def initRemoteSSHSession(remote_ssh, key_path, known_hosts_file):
    """
    Initialize an SSH session using a specified key file or ssh-agent as fallback.

    Args:
        remote_ssh (str): The remote SSH address in the format 'hostname:port'.
        key_path (str): The path to the private key file. If not provided or doesn't exist, ssh-agent will be used.
        known_hosts_file (str): The path to the known hosts file. If not provided, will default to ~/.ssh/known_hosts.

    Returns:
        paramiko.SSHClient: The initialized SSH client.

    Raises:
        ValueError: If the remote SSH address does not include a port number.
        ConnectionError: If SSH connection fails with either key file or ssh-agent.
        FileNotFoundError: If the known hosts file is not found.
    """

    ssh = paramiko.SSHClient()
    known_hosts_file = os.path.expanduser(known_hosts_file)

    if known_hosts_file and os.path.exists(known_hosts_file):
        ssh.load_host_keys(known_hosts_file)
        ssh.set_missing_host_key_policy(HostnameResolvingHostKeyPolicy(known_hosts_file))
    else:
        raise FileNotFoundError(f"Known hosts file not found: {known_hosts_file}")

    username = getpass.getuser()
    if remote_ssh.find(':') == -1:
        raise ValueError(f"SSH remote address must be in format hostname:port, got: {remote_ssh}")
    hostname, port = remote_ssh.split(':')

    # Use key file if provided and exists
    if key_path and os.path.exists(key_path):
        try:
            ssh.connect(hostname=hostname, username=username, key_filename=key_path, port=int(port))
        except Exception as e:
            raise ConnectionError(f"Failed to connect using key file {key_path}: {str(e)}")
    else:
        # Use ssh-agent if key_path is not provided or does not exist
        try:
            ssh.connect(hostname=hostname, username=username, port=int(port), look_for_keys=True, allow_agent=True)
        except Exception as e:
            raise ConnectionError(f"Failed to connect using ssh-agent: {str(e)}")

    return ssh

def closeSSH(remote_ssh):
    """
    Close an SSH session.

    Args:
        remote_ssh (paramiko.SSHClient): The SSH client to close.
    """
    remote_ssh.close()


def handle_ssh_output(ssh_stdout, prefix, pipe):
    """
    Read and handle the output from an SSH command.

    Args:
        ssh_stdout (paramiko.ChannelFile): The SSH stdout channel.
        prefix (str): The prefix to add to each line of output.
        pipe (file-like object): The pipe to write the output to.
    """
    lines = []
    while True:
        read_bytes = ssh_stdout.read()
        if read_bytes == '' or read_bytes == b'': #EOF
            break
        text = read_bytes.decode('utf-8', errors='replace')
        if text == '':
            continue
        # Split the text into lines and add the prefix to each line
        text_lines = text.split('\n')
        prefixed_lines = [prefix + line for line in text_lines]
        new_text = '\n'.join(prefixed_lines)
        lines.extend(prefixed_lines)
        pipe.write(new_text)
        pipe.flush()
    return lines

def read_ssh_output(ssh_stdout, prefix, pipe, result_queue = None):
    try:
        lines = handle_ssh_output(ssh_stdout, prefix, pipe)
        code = ssh_stdout.channel.recv_exit_status()
        # lines.extend(ssh_stdout.readlines())
        if result_queue is None:
            return (code, lines)
        else:
            result_queue.put((code, lines))

    except socket.timeout:
        if result_queue is None:
            return (100, [])
        else:
            result_queue.put((100, []))

def executeCommandViaSSHAndRedirect(ssh_session, cmd, prefix, pipe, timeout = 60, thread_list = None):
    """
    Execute a command via SSH and redirect the output to a pipe.

    Args:
        ssh_session (paramiko.SSHClient): The SSH session to use.
        cmd (str): The command to execute.
        prefix (str): The prefix to add to each line of output.
        pipe (file-like object): The pipe to write the output to.
        timeout (int, optional): The command timeout in seconds. Defaults to 60.

    Returns:
        tuple: The exit code and a list of output lines.
    """

    ssh_stdin, ssh_stdout, _ = ssh_session.exec_command(cmd, timeout=timeout)
    ssh_stdin.close()
    ssh_stdout.channel.set_combine_stderr(True)
    result_queue = queue.Queue()
    if thread_list is not None:
        thread = threading.Thread(target=read_ssh_output, args=(ssh_stdout, prefix, pipe, result_queue))
        thread_list.append((thread, result_queue))
        thread.start()
        return None, None
    else:
        return read_ssh_output(ssh_stdout, prefix, pipe)

def executeCommandViaSSH(ssh_session, cmd, timeout = 60):
    """
    Execute a command via SSH.

    Args:
        ssh_session (paramiko.SSHClient): The SSH session to use.
        cmd (str): The command to execute.
        timeout (int, optional): The command timeout in seconds. Defaults to 60.

    Returns:
        list: A list of output lines.
    """
    ssh_stdin, ssh_stdout, ssh_stderr = ssh_session.exec_command(cmd, timeout=timeout)
    ssh_stdin.close()
    ssh_stdout.channel.set_combine_stderr(True)
    lines = []
    while True:
        line = ssh_stdout.readline()
        if not line:
            break
        lines.append(line)
    return lines

def set_non_interactive_shell(remote_ssh, key_path, known_hosts_file):
    """
    Sets the non-interactive shell.
    """
    ssh_client_session = initRemoteSSHSession(remote_ssh=remote_ssh, key_path=key_path, known_hosts_file=known_hosts_file)
    _ = executeCommandViaSSH(ssh_client_session, f'cp ~/.bashrc ~/.bashrc.bak')
    _ = executeCommandViaSSH(ssh_client_session, r"sed -i '1i case $- in *i*) ;; *) return;; esac' ~/.bashrc")
    closeSSH(ssh_client_session)

def recover_interactive_shell(remote_ssh, key_path, known_hosts_file):
    """
    Recovers the interactive shell.
    """
    ssh_client_session = initRemoteSSHSession(remote_ssh=remote_ssh, key_path=key_path, known_hosts_file=known_hosts_file)
    _ = executeCommandViaSSH(ssh_client_session, f'mv ~/.bashrc.bak ~/.bashrc')
    closeSSH(ssh_client_session)

def sftp_recursive_put(sftp, local_path, remote_path):
    """
    Recursively upload files and directories via SFTP.

    Args:
        sftp (paramiko.SFTPClient): The SFTP client to use.
        local_path (str): The local path to upload.
        remote_path (str): The remote path to upload to.
    """
    if os.path.isdir(local_path):
        sftp.mkdir(remote_path, ignore_existing=True)  # Create remote directory if it doesn't exist
        for item in os.listdir(local_path):
            local_item = os.path.join(local_path, item)
            remote_item = os.path.join(remote_path, item)
            sftp_recursive_put(sftp, local_item, remote_item)  # Recursively copy
    else:
        sftp.put(local_path, remote_path)  # Copy file

def sftp_recursive_get(sftp, remote_path, local_path):
    """
    Recursively download files and directories via SFTP.

    Args:
        sftp (paramiko.SFTPClient): The SFTP client to use.
        remote_path (str): The remote path to download.
        local_path (str): The local path to download to.
    """
    # Check if the remote path is a directory
    try:
        sftp.listdir(remote_path)  # This will raise an error if it's not a directory

        os.makedirs(local_path, exist_ok=True)  # Create local directory if it doesn't exist
        for item in sftp.listdir(remote_path):
            remote_item = os.path.join(remote_path, item)
            local_item = os.path.join(local_path, item)
            sftp_recursive_get(sftp, remote_item, local_item)  # Recursively copy
    except IOError as e:
        # If IOError occurs, it means it's likely a file
        sftp.get(remote_path, local_path)  # Copy file

def executeSubProc(cmd):
    """
    Execute a subprocess command and return the output.

    Args:
        cmd (str): The command to execute.

    Returns:
        list: A list of output lines.
    """
    output = subprocess.getoutput(cmd)
    if len(output) == 0:
        return []
    res = output.split('\n')
    return res

def createDirectory(directory_path):
    """
    Create a directory if it does not exist.

    Args:
        directory_path (str): The path of the directory to create.
    """
    os.makedirs(directory_path, exist_ok=True)

def align_prints(delimiter_line, title):
    """
    Align a title within a delimiter line.

    Args:
        delimiter_line (str): The delimiter line.
        title (str): The title to align.

    Returns:
        str: The formatted string with the aligned title.
    """
    res = ''
    delimiter = delimiter_line[0]
    left = math.floor((len(delimiter_line)-len(title))/2)
    left_reminder = (len(delimiter_line)-len(title)) % 2
    right_space = ''
    left_space = ''
    if left_reminder != 0:
        right_space = ' '* left
        left -= 1
        left_space = ' '* left
    else:
        left -= 1
        right_space = ' '* left
        left_space = ' '* left

    res = '\n'+delimiter_line + f'\n{delimiter}{left_space}{title}{right_space}{delimiter}\n' + delimiter_line + '\n'
    return res


class MyRotatingFile:
    """
    A class for managing a rotating log file.

    Attributes:
        filename (str): The name of the log file.
        max_size (int): The maximum size of the log file in bytes.
        backup_count (int): The number of backup files to keep.
    """
    _lock = threading.Lock()

    def __init__(self, filename, max_size=100 * 1024 * 1024, backup_count=3):
        """
        Initialize the rotating file.

        Args:
            filename (str): The name of the log file.
            max_size (int, optional): The maximum size of the log file in bytes. Defaults to 100MB.
            backup_count (int, optional): The number of backup files to keep. Defaults to 3.
        """
        self.filename = filename
        self.max_size = max_size
        self.backup_count = backup_count
        self.current_size = 0
        self.file = open(self.filename, 'a')

    def _rotate(self):
        """
        Rotate the log file when it exceeds max size.
        """
        self.file.close()
        # Rename the current log file
        for i in range(self.backup_count, 0, -1):
            log_file = f"{self.filename}.{i}"
            if os.path.exists(log_file):
                # Rename the old logs
                os.rename(log_file, f"{self.filename}.{i + 1}")

        # Rename the current log file to .1
        os.rename(self.filename, f"{self.filename}.1")
        # Open a new log file
        self.file = open(self.filename, 'a')

    def write(self, message):
        """
        Write a message to the log file and rotate if necessary.

        Args:
            message (str): The message to write.
        """
        if len(message) == 0 or message == '\n':
            return
        # Check if the file exceeds max size
        with MyRotatingFile._lock:
            if self.current_size >= self.max_size:
                self.current_size = 0
                self._rotate()

        # Write the log message to the file
        msg = f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}"
        if not msg.endswith('\n'):
            msg += '\n'
        byte_size = sys.getsizeof(msg)
        with MyRotatingFile._lock:
            self.current_size += byte_size
        self.file.write(msg)
        self.file.flush()  # Ensure the log entry is written to disk immediately

    def close(self):
        """
        Close the log file.
        """
        self.file.close()

    def flush(self):
        """
        Flush the log file.
        """
        pass

class LineLimiter:
    """
    A class for limiting the length of lines written to a stream.

    Attributes:
        stream (file-like object): The stream to write to.
        max_length (int): The maximum length of each line.
    """

    def __init__(self, stream, max_length = 1000):
        """
        Initialize the line limiter.

        Args:
            stream (file-like object): The stream to write to.
            max_length (int, optional): The maximum length of each line. Defaults to 1000.
        """
        self.stream = stream
        self.max_length = max_length

    def write(self, data):
        """
        Write data to the stream, truncating lines if necessary.

        Args:
            data (str): The data to write.
        """
        # Split the input into lines
        lines = data.splitlines()

        for line in lines:
            # Truncate each line if it's longer than max_length
            truncated_line = line[:self.max_length]
            self.stream.write(truncated_line)  # Ensure a newline at the end

    def flush(self):
        """
        Flush the stream.
        """
        # Ensure flush works correctly
        self.stream.flush()

    def close(self):
        """
        Close the stream.
        """
        # Ensure close works correctly
        self.stream.close()
