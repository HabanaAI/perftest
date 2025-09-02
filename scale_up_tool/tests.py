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
Performance Test Implementation Module for Habana Hardware.

This module provides comprehensive performance testing capabilities for Habana hardware,
including network bandwidth, latency, and connectivity tests. It supports both local
and remote test execution with detailed result analysis and reporting.

Key Features:
- Multiple test types: ping-pong, bandwidth, latency, and HBM-to-HBM
- Both SSH-based remote execution and local subprocess execution
- Comprehensive result parsing and validation
- Support for InfiniBand and Ethernet network testing
- Detailed performance metrics collection and analysis
- Error handling and timeout management

Classes:
    BaseResult: Abstract base class for test result handling
    BWResult: Bandwidth test result parser and validator
    LatencyResult: Latency test result parser and validator
    ClientAccess: Abstract base class for test execution methods
    SSHClient: SSH-based remote test execution
    LocalClient: Local subprocess-based test execution
    test: Abstract base class for all performance tests
    perf_hbm2hbm: HBM-to-HBM memory performance tests
    perf_ping_pong: Network ping-pong latency tests
    perf_write_bw: Network bandwidth tests
    perf_write_lat: Network latency tests

Functions:
    read_subproccess_output: Subprocess output reader with timeout handling
"""

from abc import ABC, abstractmethod
import os
import queue
import select
import subprocess
import threading
import time
from utils import executeCommandViaSSHAndRedirect, align_prints, executeCommandViaSSH
import re
#import resource

#def set_core_dump():
#    # Set the core dump size to unlimited
#    resource.setrlimit(resource.RLIMIT_CORE, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))

def read_subproccess_output(result_queue, stream, timeout, proc, host_name, prefix):
    """
    Read subprocess output with timeout and stream redirection.
    
    This function monitors subprocess output streams (stdout and stderr) with
    a configurable timeout. It formats output with host identification and
    writes to both a stream and a result queue for processing.
    
    Args:
        result_queue (queue.Queue): Queue to store collected output lines
        stream: Output stream for real-time display (file-like object)
        timeout (int): Maximum time in seconds to wait for output
        proc (subprocess.Popen): Subprocess instance to monitor
        host_name (str): Host identifier for output labeling
        prefix (str): Prefix string for output line formatting
        
    Note:
        - Uses select() for non-blocking I/O monitoring
        - Handles both stdout and stderr streams
        - Includes timeout handling to prevent indefinite blocking
        - Formats output with host and prefix identification
    """
    lines = []
    start_time = time.time()
    timeout_flag = False
    while True:
        if time.time() - start_time > timeout:
            timeout_flag=True
            break
        ready_out, _, _ = select.select([proc.stdout], [], [], 0.5)  # 1-second timeout
        ready_err, _, _ = select.select([proc.stderr], [], [], 0.5)  # 1-second timeout
        if ready_out  or ready_err:
            if ready_out:
                stdout_line = proc.stdout.readline()
                if stdout_line == b'':
                    break
                output_line = f'[{prefix}:: {host_name}] ' + stdout_line.decode('utf-8', errors='replace').lstrip()
                lines.append(output_line)
                stream.write(output_line)
            if ready_err:
                stderr_line = proc.stderr.readline()
                if stderr_line == b'':
                    continue
                output_line = f'[{prefix}:: {host_name}] ' + stderr_line.decode('utf-8', errors='replace').lstrip()
                lines.append(output_line)
                stream.write(output_line)
        else:
            time.sleep(0.5)

    if timeout_flag:
        stream.write(f'[{prefix}:: {host_name}] Timeout reached, terminating the process')
        proc.terminate()
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
    else:
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()


    output_lines = []
    output_lines.extend(stderr.decode('utf-8', errors='replace').split('\n'))
    output_lines.extend(stdout.decode('utf-8', errors='replace').split('\n'))
    output_lines = [f'[{prefix}:: {host_name}] ' + line.lstrip() for line in output_lines]

    lines.extend(output_lines)
    stream.write('\n'.join(output_lines))

    result_queue.put(lines)
class BaseResult(ABC):
    """
    Abstract base class for performance test result handling.
    
    This class defines the interface for parsing, validating, and comparing
    performance test results. It provides a common framework for different
    types of performance metrics (bandwidth, latency, etc.).
    
    Key Features:
    - Abstract comparison operators for result validation
    - Common interface for different result types
    - Framework for pass/fail criteria evaluation
    
    Abstract Methods:
        __eq__, __ne__, __lt__, __gt__: Comparison operators for results
        Other result-specific methods as needed by subclasses
    """
    def __init__(self):
        """Initialize the base result handler."""
        super().__init__()

    @abstractmethod
    def __eq__(self, value):
        """
        Check if this result equals another value.
        
        Args:
            value: Value to compare against
            
        Returns:
            bool: True if equal, False otherwise
        """
        pass
    @abstractmethod
    def __ne__(self, value):
        """
        Check if this result does not equal another value.
        
        Args:
            value: Value to compare against
            
        Returns:
            bool: True if not equal, False otherwise
        """
        pass
    @abstractmethod
    def __lt__(self, value):
        """
        Check if this result is less than another value.
        
        Args:
            value: Value to compare against
            
        Returns:
            bool: True if less than, False otherwise
        """
        pass
    @abstractmethod
    def __gt__(self, value):
        """
        Check if this result is greater than another value.
        
        Args:
            value: Value to compare against
            
        Returns:
            bool: True if greater than, False otherwise
        """
        pass
    @abstractmethod
    def __le__(self, value):
        pass
    @abstractmethod
    def __ge__(self, value):
        pass
    @abstractmethod
    def __str__(self):
        pass
    @abstractmethod
    def checkCriteria(self, criteria):
        pass
class BWResult(BaseResult):
    def __init__(self, bw):
        self.bw = bw
    def __eq__(self, value):
        return self.bw == value
    def __ne__(self, value):
        return self.bw != value
    def __lt__(self, value):
        return self.bw < value
    def __gt__(self, value):
        return self.bw > value
    def __le__(self, value):
        return self.bw <= value
    def __ge__(self, value):
        return self.bw >= value
    def __str__(self):
        return f'{self.bw}Gbps'
    def checkCriteria(self, criteria):
        return self.bw >= criteria

class LatencyResult(BaseResult):
    def __init__(self, avg, min, max):
        self.avg = avg
        self.min = min
        self.max = max

    def __eq__(self, value):
        return self.avg == value
    def __ne__(self, value):
        return self.avg != value
    def __lt__(self, value):
        return self.avg < value
    def __gt__(self, value):
        return self.avg > value
    def __le__(self, value):
        return self.avg <= value
    def __ge__(self, value):
        return self.avg >= value
    def __str__(self):
        if self.min != None and self.max != None and self.avg != None:
            return f'Average: {self.avg}us Min: {self.min}us Max: {self.max}us'
        elif self.avg != None:
            return f'Average: {self.avg}us'

    def checkCriteria(self, criteria):
        return self.avg <= criteria

class ClientAccess(ABC):
    def __init__(self, stream, host_name, timeout):
        super().__init__()
        self.stream = stream
        self.host_name = host_name
        self.timeout = timeout

    @abstractmethod
    def execute(self, cpu, server_ip, exec, args):
        pass
    @abstractmethod
    def close(self):
        pass
    @abstractmethod
    def terminate(self):
        pass

class SSHClient(ClientAccess):
    def __init__(self, ssh_session, current_path, stream, host_name, timeout):
        super().__init__(stream, host_name, timeout)
        self.ssh_session = ssh_session
        self.thread_client_list = []
        self.__client_command = None
        self.current_path = current_path

    def execute(self, cpu, server_ip, exec, args):
        variables = []
        # Open the file in read mode
        with open(f'{os.environ["HOME"]}/.ENV_SCALEUP', 'r') as file:
            # Read all lines into a list and strip newline characters
            variables = [line.strip() for line in file]
        affinity_coammnd = ''
        if cpu is not None:
            affinity_coammnd = f'taskset -c {cpu}'
        self.__client_command = f'{self.current_path}/../{exec} "{server_ip}" {" ".join(args)}'
        wrap_command = f'{" ".join(variables)} {affinity_coammnd} {self.__client_command}'
        self.stream.write(f'[client:: {self.host_name}] {wrap_command}')
        executeCommandViaSSHAndRedirect(self.ssh_session,
                                            wrap_command,
                                            f'[client:: {self.host_name}] ',
                                            self.stream,
                                            self.timeout,
                                            self.thread_client_list)

    def close(self):
        client_thread, client_queue = self.thread_client_list.pop()
        client_thread.join()  # Wait for the client thread to complete

        client_return_code, client_lines = client_queue.get()  # Get the result from the queue
        return client_return_code, client_lines

    def terminate(self):
        """
        Terminate the client test.

        Args:
            stream: The stream to write the output to.
        """
        grep_command = f'ps -aux | grep "{self.__client_command}" | grep grep -v'
        pid_list = executeCommandViaSSH(self.ssh_session, f'{grep_command} | ' + "awk '{print $2}'")
        command_list = executeCommandViaSSH(self.ssh_session, grep_command)
        self.stream.write(f'client pid list: {pid_list}')
        self.stream.write(f'client command list: {command_list}')
        if len(pid_list) >0:
            pid = pid_list[0].strip()
            kill_command = f'kill -15 {pid}'
            executeCommandViaSSH(self.ssh_session, kill_command)
            start_time = time.time()
            while len(pid_list) > 0:
                time.sleep(1)
                if time.time() - start_time > 20:
                    break
                pid_list = executeCommandViaSSH(self.ssh_session, f'{grep_command} | ' + "awk '{print $2}'")
                self.stream.write(f'client pid list after kill: {pid_list}')

class LocalClient(ClientAccess):
    def __init__(self, stream, host_name, timeout):
        super().__init__(stream, host_name, timeout)
        self.test_proc = None
        self.prints_result_queue = queue.Queue()
        self._read_thread = None

    def execute(self, cpu, server_ip, exec, args):
        env = os.environ.copy()
        variables = []
        env_file_path = f'{os.environ["HOME"]}/.ENV_SCALEUP'
        if os.path.exists(env_file_path):
            with open(env_file_path, 'r') as file:
                # Read all lines into a list and strip newline characters
                variables = [line.strip() for line in file]
        for var in variables:
            var = var.split('=')
            env[var[0]] = var[1]

        affinity_args = []
        if cpu is not None:
            affinity_args = ['taskset', '-c', str(cpu)]

        args = affinity_args + [f'../{exec}', f'{server_ip}'] + args
        self.stream.write(f'[client:: {self.host_name}] {" ".join(args)}')
        self.test_proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        self._read_thread = threading.Thread(target=read_subproccess_output, args=(self.prints_result_queue, self.stream, self.timeout, self.test_proc, self.host_name, 'client'))
        self._read_thread.start()

    def close(self):
        self._read_thread.join()  # Wait for the thread to complete
        server_lines = self.prints_result_queue.get()  # Get the result from the queue
        return_code = self.test_proc.wait()
        self.test_proc = None

        return return_code, server_lines

    def terminate(self):
        if self.test_proc != None and self.test_proc.poll() is None:
            self.test_proc.terminate()
            self.test_proc.communicate()


class test(ABC):
    """
    Abstract base class for performance tests.
    """
    def __init__(self,
                 client_host_name: str,
                 client_ip: str,
                 server_host_name: str,
                 server_ip: str,
                 device: str) -> None:
        """
        Initialize the test with client and server host names, IPs, and device.

        Args:
            client_host_name (str): The hostname of the client.
            client_ip (str): The IP address of the client.
            server_host_name (str): The hostname of the server.
            server_ip (str): The IP address of the server.
            device (str): The device to be used for the test.
        """
        super().__init__()
        self.exec =                 None
        self.server_test_proc =     None
        self.client_host_name =     client_host_name
        self.client_ip =            client_ip
        self.server_host_name =     server_host_name
        self.server_ip =            server_ip
        self.device =               device
        self.client_ssh_session =   None
        self.client_command =       None
        self.client_ib =            None
        self.server_ib =            None
        self.thread_client_list =   []
        self.prints_result_server_queue = queue.Queue()
        self.read__server_thread = None
        self.timeout_value = 20

    def setRemoteSSH(self, ssh_session):
        """
        Set the SSH session for the client.

        Args:
            ssh_session: The SSH session object.
        """
        self.client_ssh_session =   ssh_session

    def getResult(self, lines):
        """
        Parse the result from the given lines.

        Args:
            lines (list): The lines of output to parse.

        Returns:
            The parsed result.
        """
        return None

    def getTimeoutValue(self):
        """
        Get the timeout value for the test.

        Returns:
            int: The timeout value in seconds.
        """
        return self.timeout_value

    def terminateClient(self, stream):
        """
        Terminate the client test.

        Args:
            stream: The stream to write the output to.
        """
        grep_command = f'ps -aux | grep "{self.client_command}" | grep grep -v'
        pid_list = executeCommandViaSSH(self.client_ssh_session, f'{grep_command} | ' + "awk '{print $2}'")
        command_list = executeCommandViaSSH(self.client_ssh_session, grep_command)
        stream.write(f'client pid list: {pid_list}')
        stream.write(f'client command list: {command_list}')
        if len(pid_list) >0:
            pid = pid_list[0].strip()
            kill_command = f'kill -15 {pid}'
            executeCommandViaSSH(self.client_ssh_session, kill_command)
            start_time = time.time()
            while len(pid_list) > 0:
                time.sleep(1)
                if time.time() - start_time > 20:
                    break
                pid_list = executeCommandViaSSH(self.client_ssh_session, f'{grep_command} | ' + "awk '{print $2}'")
                stream.write(f'client pid list after kill: {pid_list}')

    def close(self,client_access=None, stream=None):
        """
        Close the server test process and clean up. Also, terminate the client test if needed.

        Args:
            stream: The stream to write the output to. Defaults to None.

        Returns:
            tuple: The server return code, server result, client return code, and client result.
        """
        if self.server_test_proc != None and stream == None:
            self.server_test_proc.terminate()
            self.server_test_proc.communicate()
            self.server_test_proc = None

        if self.server_test_proc != None and stream != None:
            self.read__server_thread.join()  # Wait for the thread to complete
            server_lines = self.prints_result_server_queue.get()  # Get the result from the queue

            client_return_code, client_lines = client_access.close()

            server_result = self.getResult(server_lines)
            client_result = self.getResult(client_lines)

            server_return_code = self.server_test_proc.wait()
            self.server_test_proc = None
            client_access.terminate()

            return server_return_code, server_result, client_return_code, client_result

    def launchServerTest(self) -> None:
        """
        Launch the server-side test.
        """
        pass

    def launchClientTest(self) -> None:
        """
        Launch the client-side test.
        """
        pass

    def printHeader(self) -> None:
        """
        Print the header for the test.
        """
        pass


#########################################################################################
#                               HabPerfTest                                             #
#########################################################################################
class perf_hbm2hbm(test):
    """
    Performance test for HBM to HBM communication.
    """
    def __init__(self,
                    client_host_name: str,
                    client_ip: str,
                    server_host_name: str,
                    server_ip: str,
                    tcp_port: str,
                    current_path: str,
                    rx_depth: str,
                    iters: str,
                    size: str,
                    chk: bool) -> None:
        """
        Initialize the HBM to HBM performance test.
        """
        super().__init__(client_host_name=client_host_name, client_ip=client_ip, server_host_name=server_host_name, server_ip=server_ip, device=None)

        self.__tcp_port = None

        self.current_path = current_path
        self.exec = 'perf_test'
        self.test_switch = None

        self.__rx_depth          = rx_depth
        self.__tcp_port_start    = tcp_port
        self.__iters             = iters
        self.__size              = size
        self.__chk               = chk

    def launchTest(self, c_ib_dev, c_ib_port, c_cpu, c_gid, r_ib_dev, r_ib_port, r_cpu, r_gid, stream) -> None:
        """
        Launch the test with the given IB devices and ports.
        """
        client_access = None
        if self.client_ssh_session == None: # internals testing
            client_access = LocalClient(stream, self.server_host_name, self.getTimeoutValue())
            timeout_exit_code = 1
        else: # external testing
            client_access = SSHClient(self.client_ssh_session, self.current_path, stream, self.client_host_name, self.getTimeoutValue())
            timeout_exit_code = 100

        offset = int(c_ib_dev.strip().split('_')[1])
        self.__tcp_port = self.__tcp_port_start + int(offset)
        retry = 3
        while retry > 0:
            self.launchServerTest(c_ib_dev, c_ib_port, c_cpu, c_gid, stream)
            self.launchClientTest(client_access, r_ib_dev, r_ib_port, r_cpu, r_gid)
            server_return_code, server_result, client_return_code, client_result = self.close(client_access, stream)
            if server_return_code == 1 and client_return_code == timeout_exit_code:
                time.sleep(0.25)
                retry -= 1
            else:
                break
        return server_return_code, client_return_code, server_result, client_result

    def __getArgs(self, ib_dev, ib_port, gid):
        """
        Get the arguments for the test command.
        """
        arguments = [
                        '-t', self.test_switch,
                        '-p', str(self.__tcp_port),
                        '-d', ib_dev,
                        '-i', str(ib_port),
                        '-g', str(gid),
                        '-n', self.__iters,
                        '-r', self.__rx_depth,
                        '-s', self.__size
                    ]
        if self.__chk:
           arguments.append('-c')
        return arguments

    def launchServerTest(self, c_ib_dev, c_ib_port, c_cpu, c_gid, stream) -> None:
        """
        Launch the server-side test with the given IB device and port.
        """
        self.server_ib = c_ib_dev
        env = os.environ.copy()
        variables = []
        env_file_path = f'{os.environ["HOME"]}/.ENV_SCALEUP'
        if os.path.exists(env_file_path):
            with open(env_file_path, 'r') as file:
                # Read all lines into a list and strip newline characters
                variables = [line.strip() for line in file]
        for var in variables:
            var = var.split('=')
            env[var[0]] = var[1]

        affinity_args = []
        if c_cpu is not None:
            affinity_args = ['taskset', '-c', str(c_cpu)]

        args = affinity_args + [f'../{self.exec}'] + self.__getArgs(c_ib_dev, c_ib_port, c_gid)
        stream.write(f'[server:: {self.server_host_name}] {" ".join(args)}')
        #self.server_test_proc = subprocess.Popen(args, preexec_fn=set_core_dump, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        self.server_test_proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        self.read__server_thread = threading.Thread(target=read_subproccess_output, args=(self.prints_result_server_queue, stream, self.getTimeoutValue(), self.server_test_proc, self.server_host_name, 'server'))
        self.read__server_thread.start()

    def launchClientTest(self, client_access, r_ib_dev, r_ib_port, r_cpu, r_gid) ->None:
        """
        Launch the client-side test with the given IB device and port.
        """
        self.client_ib = r_ib_dev

        client_access.execute(r_cpu, self.server_ip, self.exec, self.__getArgs(r_ib_dev, r_ib_port, r_gid))

    def printHeader(self) -> None:
        """
        Print the header for the HBM to HBM test.
        """
        print('=========================================')
        print('=             HBM to HBM                =')
        print('=========================================\n\n')
        print(align_prints('-----------------------------------------', f'{self.__class__.__name__}'))

#########################################################################################
#                               Ping-Pong                                               #
#########################################################################################
class perf_ping_pong(perf_hbm2hbm):
    """
    Performance test for Ping-Pong communication.
    """
    def __init__(self,
                    client_host_name: str,
                    client_ip: str,
                    server_host_name: str,
                    server_ip: str,
                    tcp_port: str,
                    current_path: str,
                    rx_depth: str,
                    iters: str,
                    size: str,
                    chk: bool) -> None:
        """
        Initialize the Ping-Pong performance test.
        """
        super().__init__( client_host_name, client_ip, server_host_name, server_ip, tcp_port, current_path, rx_depth, iters, size, chk)
        self.test_switch = 'pp'

#########################################################################################
#                               Latency                                                 #
#########################################################################################

class perf_write_lat(perf_hbm2hbm):
    """
    Performance test for write latency.
    """
    def __init__(self,
                    client_host_name: str,
                    client_ip: str,
                    server_host_name: str,
                    server_ip: str,
                    tcp_port: str,
                    current_path: str,
                    rx_depth: str,
                    iters: str,
                    size: str) -> None:
        """
        Initialize the write latency performance test.
        """
        super().__init__( client_host_name, client_ip, server_host_name, server_ip, tcp_port, current_path, rx_depth, iters, size, False)
        self.test_switch = 'lt'
        self.timeout_value = 40

    def getResult(self, lines):
        """
        Parse the result from the given lines to extract Latency.
        """
        pattern_avg = r'Average\s+Latency:\s*([\d.]+)'
        pattern_min = r'Min\s+Latency:\s*([\d.]+)'
        pattern_max = r'Max\s+Latency:\s*([\d.]+)'
        avg = None
        min = None
        max = None
        for line in lines:
            avg_match = re.search(pattern_avg, line)
            if avg_match:
                avg = float(avg_match.group(1))
                continue
            min_match = re.search(pattern_min, line)
            if min_match:
                min = float(min_match.group(1))
                continue
            max_match = re.search(pattern_max, line)
            if max_match:
                max = float(max_match.group(1))
                continue
        return LatencyResult(avg, min, max) if avg != None else None

#########################################################################################
#                               Bandwidth                                               #
#########################################################################################
class perf_write_bw(perf_hbm2hbm):
    """
    Performance test for write bandwidth.
    """
    def __init__(self,
                    client_host_name: str,
                    client_ip: str,
                    server_host_name: str,
                    server_ip: str,
                    tcp_port: str,
                    current_path: str,
                    rx_depth: str,
                    iters: str,
                    size: str) -> None:
        """
        Initialize the write bandwidth performance test.
        """
        super().__init__( client_host_name, client_ip, server_host_name, server_ip, tcp_port, current_path, rx_depth, iters, size, False)
        self.test_switch = 'bw'

    def getResult(self, lines):
        """
        Parse the result from the given lines to extract RX Bandwidth.
        """
        pattern = r'RX Bandwidth:\s*([\d.]+)'
        for line in lines:
            match = re.search(pattern, line)
            if match:
                return BWResult(float(match.group(1)))
        return None