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
Test Suite Framework for Habana Performance Testing Tool.

This module provides the core test suite framework for executing distributed
performance tests across Habana hardware. It includes abstract base classes,
concrete implementations, and coordination logic for complex test scenarios.

Key Features:
- Abstract test suite framework for extensibility
- Multi-host test coordination and execution
- InfiniBand device and port management
- Test result aggregation and reporting
- Support for various network topologies
- Parallel test execution with resource management

Classes:
    Suite: Abstract base class for all test suites
    Flow: Abstract base class for test execution flows
    PerfTest: Concrete implementation for network performance testing

Functions:
    job: Worker function for parallel test execution
"""

from abc import ABC, abstractmethod
import json
import re
import sys
import time
from tqdm import tqdm
import multiprocessing
import itertools
import shutil
import os

from tests import (
    perf_ping_pong,
    perf_write_lat,
    perf_write_bw
)

from utils import (
    initRemoteSSHSession,
    executeCommandViaSSH,
    executeSubProc,
    createDirectory,
    closeSSH,
    cyclic_iteration,
    print_,
    MyRotatingFile,
    LineLimiter,
    align_prints,
    set_non_interactive_shell,
    recover_interactive_shell,
    getPermutationsFullDuplex,
    getPermutations
)



def job(queue, test, ssh_args, output_directory, c_ib_dev, c_ib_port, c_cpu, c_gid_list, r_ib_dev, r_ib_port, r_cpu, r_gid_list):
    """
    Execute a performance test job in a worker process.

    This function serves as a worker process entry point for parallel test execution.
    It establishes SSH connections, configures InfiniBand devices, launches tests,
    and collects results for aggregation by the parent process.

    Args:
        queue (multiprocessing.Queue): Queue to store test results and output
        test: Test object instance to be executed
        ssh_args (tuple): SSH connection parameters (host:port, key_path, known_hosts)
        output_directory (str): Local directory path for storing test output
        c_ib_dev (str): Client InfiniBand device identifier
        c_ib_port (str): Client InfiniBand port number
        c_cpu (str): Client CPU affinity setting
        c_gid_list (list): Client GID (Global Identifier) list
        r_ib_dev (str): Remote InfiniBand device identifier
        r_ib_port (str): Remote InfiniBand port number
        r_cpu (str): Remote CPU affinity setting
        r_gid_list (list): Remote GID (Global Identifier) list

    Note:
        - Runs in separate process context for parallel execution
        - Handles SSH session management and cleanup
        - Returns results via multiprocessing queue
        - Includes comprehensive error handling for network issues
    """
    ssh_session = None
    if ssh_args != None:
        ssh_session = initRemoteSSHSession(*ssh_args)
        test.setRemoteSSH(ssh_session)
    file = None
    name = f"{output_directory}/{r_ib_port}.txt"
    try:
        # Open a file in write mode
        file = MyRotatingFile(name)
        stream = LineLimiter(file)
        if not c_gid_list or not r_gid_list:
            raise BaseException("c_gid_list and r_gid_list must be non-empty.")
        if len(c_gid_list) != len(r_gid_list):
            raise BaseException("c_gid_list and r_gid_list must have the same length.")
        for c_gid, r_gid in zip(c_gid_list, r_gid_list):
            if c_gid is None or r_gid is None:
                raise BaseException('GID is None, please check the GID configuration')
            print('From:',file=stream)
            print(f'    ib_dev: {c_ib_dev}',file=stream)
            print(f'    ib_port: {c_ib_port}',file=stream)
            print(f'    gid: {c_gid}',file=stream)
            if c_cpu != None:
                print(f'    cpu: {c_cpu}',file=stream)
            else:
                print(f'    WARNING: no NUMA node, can lead to perfromance degradation',file=stream)
            print('To:',file=stream)
            print(f'    ib_dev: {r_ib_dev}',file=stream)
            print(f'    ib_port: {r_ib_port}',file=stream)
            print(f'    gid: {r_gid}',file=stream)
            if r_cpu != None:
                print(f'    cpu: {r_cpu}',file=stream)
            else:
                print(f'    WARNING: no NUMA node, can lead to perfromance degradation',file=stream)
            sever_return_code, client_return_code, server_result, client_result = test.launchTest(c_ib_dev, c_ib_port, c_cpu, c_gid, r_ib_dev, r_ib_port, r_cpu, r_gid, stream)
            if sever_return_code == 0 and client_return_code == 0:
                break

        queue.put((sever_return_code, client_return_code, server_result, client_result, c_ib_dev, c_ib_port, r_ib_dev, r_ib_port))
    except Exception as e:
        print(f'Error: {e}', file=stream)
        queue.put((None, None, None, None, c_ib_dev, c_ib_port, r_ib_dev, r_ib_port))
    finally:
        if stream != None:
            stream.close()
        if ssh_session != None:
            closeSSH(ssh_session)
        test.setRemoteSSH(None)


class Suite(ABC):
    """
    Abstract base class for performance test suites.

    This class provides the foundational framework for all performance test suites
    in the Habana testing system. It manages device configuration, host connections,
    test execution coordination, and result aggregation.

    Key Responsibilities:
    - Device and network topology management
    - SSH connection handling for remote hosts
    - Test execution lifecycle management
    - Result collection and reporting
    - Error handling and cleanup

    Attributes:
        device (str): Target device identifier for testing
        exec: Test execution engine instance
        client_ip (str): IP address of client host
        client_host_name (str): Hostname of client host
        server_ip (str): IP address of server host
        server_host_name (str): Hostname of server host
        at_least_one_failed (bool): Flag indicating if any tests failed

    Abstract Methods:
        Subclasses must implement specific test execution logic.
    """
    def __init__(self, device: str, server_hostname: str, client_hostname: str, test_type: str) -> None:
        """
        Initialize the test suite with host and device configuration.

        Sets up the basic configuration for a test suite including device selection,
        host identification, and test type specification. Handles both single-host
        and multi-host test scenarios.

        Args:
            device (str): Device identifier for the target hardware
            server_hostname (str): Hostname or IP of the server host
            client_hostname (str): Hostname or IP of the client host (empty for single-host)
            test_type (str): Type of performance test to execute

        Note:
            - Empty client_hostname indicates single-host testing
            - Special syntax "(&&" in hostname enables command execution
            - Automatically resolves hostnames to IP addresses
        """
        super().__init__()
        self.device = device
        self.exec = None
        if client_hostname == '':
            self.client_ip = None
            self.client_host_name = None
        elif "(&&" in client_hostname:
            client_parts = client_hostname.split("(")
            self.client_ip = client_parts[0]
            self.client_host_name = client_parts[1].split(")")[0].strip('&&')
        else:
            self.client_ip = client_hostname
            self.client_host_name = client_hostname
        if "(&&" in server_hostname:
            server_parts = server_hostname.split("(")
            self.server_ip = server_parts[0]
            self.server_host_name = server_parts[1].split(")")[0].strip('&&')
        else:
            self.server_ip = server_hostname
            self.server_host_name = server_hostname
        self.test_type = test_type
        self.test_dict = None
        self.specificTitle = None
        self.report_name = None
        self.logs_dir_path = None
        self.__ipc = None
        self.flow = None

    def close(self) ->None:
        """
        Closes the suite, terminates any running processes, and prints the report.
        """
        if self.__ipc != None:
            for proc, _ in self.__ipc:
                if proc.is_alive():
                    proc.terminate()
                    proc.join()  # Ensure the process has terminated
        if self.test_dict != None:
            for _, test in self.test_dict.items():
                test.close()
        if self.flow != None:
            self.flow.close()
        if self.report_name != None:
            with open(f'{self.report_name}', 'r') as file:
                # Read the file content
                content = file.read()
                # Print the content to stdout
                print(f'{content}', flush=True)
            self.report_name = None

    def printHeader(self, file=sys.stdout) -> None:
        """
        Prints the header information for the suite.

        Args:
            file: File object to print the header to. Defaults to sys.stdout.
        """
        star_line = '**********************************************************************************'
        title = f'{self.specificTitle}: {self.test_type} - '
        for k,v in self.titleConfig.items():
            title += f' {k}: {v}'
        aligned_title = align_prints(star_line, title)
        print(aligned_title, file=file, flush=True)
        print(f'Server: {self.server_host_name}', file=file, flush=True)
        if self.client_host_name != None:
            print(f'Client: {self.client_host_name}\n', file=file, flush=True)

    def apply(self) -> None:
        """
        Applies the suite by executing the test and printing the header.
        """
        self.printHeader()
        test = self.test_dict[self.test_type]
        test.printHeader()
        test.launchTest()

class Flow(ABC):
    """
    Abstract base class for test execution flows.

    This class defines the interface and common functionality for test execution
    flows that coordinate the sequence of operations needed to run performance
    tests across different network configurations and topologies.

    Key Responsibilities:
    - Progress tracking and metadata management
    - SSH connection parameter management
    - Test iteration counting and coordination
    - Network configuration state management

    Attributes:
        pbar: Progress bar instance for visual feedback
        currentNetwork: Current network configuration being tested
        currentPath (str): Base path for test execution and output

    Abstract Methods:
        Subclasses must implement flow-specific execution logic.
    """
    def __init__(self, path: str) -> None:
        """
        Initialize the test execution flow.

        Args:
            path (str): Base directory path for test execution and output storage
        """
        super().__init__()
        self.pbar = None
        self.currentNetwork = None
        self.currentPath = path

    def dumpMetadata(self, time_stampe):
        """
        Dump test metadata to a temporary file for progress tracking.

        Creates a metadata file containing information about the total number
        of test iterations, which is used by progress monitoring systems.

        Args:
            time_stampe (str): Timestamp identifier for the metadata file
        """
        with open(f'/tmp/perftest_metadata{time_stampe}.json', 'w') as file:
            json.dump({
                'total_iterations': self.getTotalIterations()
            }, file)

    def setPbar(self, pbar: tqdm) -> None:
        """
        Set the progress bar instance for this flow.

        Args:
            pbar (tqdm): Progress bar instance for visual progress tracking
        """
        self.pbar = pbar

    def getSSHArgs(self) -> tuple:
        """
        Get SSH connection arguments for remote test execution.

        Returns:
            tuple: SSH connection parameters (host, key_path, known_hosts_file)

        Note:
            Subclasses must implement this method to provide appropriate
            SSH connection parameters for their specific use cases.
        """
        pass

    def getCurrentNetwork(self) -> str:
        """
        Gets the current network.

        Returns:
            str: Current network.
        """
        return self.currentNetwork

    @abstractmethod
    def getTotalIterations(self) -> int:
        """
        Gets the total number of iterations.

        Returns:
            int: Total number of iterations.
        """
        pass

    @abstractmethod
    def iterate(self):
        """
        Iterates over the connections.
        """
        pass

    def close(self) -> None:
        """
        Closes the flow.
        """
        pass

    def get_numa_info(self, shell_func):
        """
        Get NUMA node information using numactl and lscpu.

        Args:
            shell_func (function): Function to execute shell commands.

        Returns:
            dict: A dictionary containing NUMA node information.
        """
        numa_info = {}

        # Get NUMA node information using lscpu
        lscpu_output = shell_func('lscpu -e=CPU,NODE')

        # Skip the header line
        for line in lscpu_output[1:]:
            cpu, node = line.strip().split()
            cpu = int(cpu)
            node = int(node)
            if node not in numa_info:
                numa_info[node] = []
            numa_info[node].append(cpu)

        return numa_info

    def extractDeviceNumaInfo(self, numa_info, shell_func):
        device_numa_info={}
        bus_info = shell_func('hl-smi -Q bus_id,index -f csv,noheader')
        for line in bus_info:
            bus_id, index = line.strip().split(',')
            lspci_output = shell_func(f'lspci -s {bus_id} -v | grep NUMA')
            lspci_output = [line for line in lspci_output if 'NUMA' in line]
            if len(lspci_output) == 0:
                #numa_info[0].pop()
                device_numa_info[int(index)] = None
                continue
            lspci_output = lspci_output[0].strip()
            pattern = r'NUMA node (\d+)'
            match = re.search(pattern, lspci_output)
            if match:
                numa_node = int(match.group(1))
            else:
                device_numa_info[int(index)] = None
                continue
            if numa_node not in numa_info.keys():
                device_numa_info[int(index)] = None
                continue
            if len(numa_info[numa_node]) == 0:
                device_numa_info[int(index)] = None
                continue

            cpu = numa_info[numa_node].pop()
            device_numa_info[int(index)] = cpu
        return device_numa_info

    def extractPortsInfo(self, shell_func):

        #generate port info csv file
        lines = shell_func(f'{self.currentPath}/../mapping /tmp/port_info.csv > /dev/null 2>&1 && cat /tmp/port_info.csv && rm /tmp/port_info.csv')

        res = {}
        for line in lines:
            parts = line.strip().split(',')
            if line.startswith('#'):
                continue
            hbl_index = int(parts[0])
            dev_port = int(parts[1])
            ib_port = int(parts[2])
            mac_addr = parts[3]
            if hbl_index not in res.keys():
                res[hbl_index] = []
            res[hbl_index].append((dev_port, ib_port, mac_addr))

        return res


class ExternalFlow(Flow):
    def __init__(self, path: str) -> None:
        super().__init__(path)
        self.connections = None


    def extract(self, netowrk_dict, ports_info, device_numa_info, gid_info):
        """
        Extracts network information.

        Args:
            netowrk_dict (dict): Network dictionary.
            mac_info (dict): MAC information.
            device_numa_info (dict): Device NUMA information.
            gid_info (dict): GID information.

        Returns:
            dict: Extracted network information.
        """
        res = {}
        # Regular expression to match the first two numbers
        pattern = r'(?P<first_number>\d+)\.(?P<second_number>\d+)'

        network_config = netowrk_dict['NIC_NET_CONFIG']
        for nic in network_config:
            # Search for the pattern in the IP address string
            match = re.search(pattern, nic['NIC_IP'])

            # Extract the numbers using the named groups
            if match:
                first_number = match.group('first_number')
                second_number = match.group('second_number')

            else:
                raise BaseException("nic doesn't have IP4 address")
            ip = f'{first_number}.{second_number}.0.0'

            if nic['NIC_MAC'] not in ports_info.keys():
                raise BaseException(f'Not found mac address in ports info: mac: {nic["NIC_MAC"]} ports_info: {ports_info}')
            device_index, ib_port = ports_info[nic['NIC_MAC']]

            if device_index == None or ib_port == None:
                raise BaseException('Not found device index or device port')
            if device_index not in gid_info.keys() or ib_port not in gid_info[device_index].keys():
                raise BaseException(f'Not found gid info for device index or device port, device index: {device_index}, device port: {ib_port}, gid_info: {gid_info}')
            if ip in res.keys():
                res[ip].append((device_index, ib_port, device_numa_info[device_index], gid_info[device_index][ib_port]))
            else:
                res[ip] = [(device_index, ib_port, device_numa_info[device_index], gid_info[device_index][ib_port])]

        return res

    def extractDeviceGidInfo(self, shell_func):
        devices_gid_info={}
        gid_info = shell_func('for file in /sys/class/infiniband/hbl_*/ports/*/gid_attrs/types/*; do echo "$file"; cat "$file"; done')
        pattern = r'hbl_(\d+)/ports/(\d+)/gid_attrs/types/(\d+)'
        for gid_path, value in zip(gid_info[::2], gid_info[1::2]):
            value = value.strip().lower()
            if 'roce' in value and 'v2' in value:
                match = re.search(pattern, gid_path)
                if match:
                    device = int(match.group(1))
                    port = int(match.group(2))
                    gid = int(match.group(3))
                    _ = devices_gid_info.setdefault(device, {}).setdefault(port, [])
                    if gid not in devices_gid_info[device][port]:
                        devices_gid_info[device][port].append(gid)

        return devices_gid_info

    def extractPortsInfo(self, shell_func):
        info = super().extractPortsInfo(shell_func)
        res = {}
        for device_index, info in info.items():
            for _, ib, mac in info:
                if mac == '--':
                    continue
                if mac in res.keys():
                    raise BaseException(f'Found duplicate ib ports for the same mac address: mac address = {mac}, [(device_index, ib_port)] = [{res[mac]} , {(device_index, ib)}]')
                res[mac] = (device_index, ib)
        return res

    def get_local_hls_Info(self):
        """
        Gets local HLS information.

        Returns:
            dict: Local HLS information.
        """
        #external ports
        gaudinetPath = os.getenv('GAUDINET_PATH')
        if gaudinetPath == None:
            raise BaseException('GAUDINET_PATH is not defined in the server side')
        netowrk_dict = json.loads("".join(executeSubProc(f'cat {gaudinetPath}')))
        ports_info = self.extractPortsInfo(shell_func=executeSubProc)
        setup_numa_info = self.get_numa_info(shell_func=executeSubProc)
        device_numa_info = self.extractDeviceNumaInfo(setup_numa_info, shell_func=executeSubProc)
        device_gid_info = self.extractDeviceGidInfo(shell_func=executeSubProc)


        return self.extract(netowrk_dict, ports_info, device_numa_info, device_gid_info)

class RemoteFlow(ExternalFlow):
    def __init__(self, client_ip: str, ssh_port: int, ssh_key_file: str, known_hosts_file: str, path: str, basic_check: bool, time_stampe: str) -> None:
        super().__init__(path)

        self.ssh_args = (client_ip+f":{ssh_port}", ssh_key_file, known_hosts_file)
        set_non_interactive_shell(*self.ssh_args)

        self.connections = self.getExternalConnections( basic_check)
        if len(self.connections.keys()) == 0:
            raise BaseException('No connections found')
        self.currentNetwork = next(iter(self.connections.keys()))
        self.dumpMetadata(time_stampe)

    def getSSHArgs(self):
        return self.ssh_args

    def close(self) -> None:
        """
        Closes the external flow.
        """
        recover_interactive_shell(*self.ssh_args)

    def get_remote_hls_Info(self):
        """
        Gets remote HLS information.

        Returns:
            dict: Remote HLS information.
        """
        gaudinetPath = os.getenv('GAUDINET_PATH')
        if gaudinetPath == None:
            raise BaseException(f'GAUDINET_PATH is not defined in the client side {self.ssh_args[0]}')
        ssh_session = initRemoteSSHSession(*self.ssh_args)
        netowrk_dict = json.loads("".join(executeCommandViaSSH(ssh_session, f'cat {gaudinetPath}')))
        ports_info = self.extractPortsInfo(shell_func=lambda cmd: executeCommandViaSSH(ssh_session, cmd))
        setup_numa_info = self.get_numa_info(shell_func=lambda cmd: executeCommandViaSSH(ssh_session, cmd))
        device_numa_info = self.extractDeviceNumaInfo(setup_numa_info, shell_func=lambda cmd: executeCommandViaSSH(ssh_session, cmd))
        device_gid_info = self.extractDeviceGidInfo(shell_func=lambda cmd: executeCommandViaSSH(ssh_session, cmd))
        closeSSH(ssh_session)

        return self.extract(netowrk_dict, ports_info, device_numa_info, device_gid_info)

    def getExternalConnections(self, basic_check = False):
        """
        Creates device pairing permutations for parallel execution.

        Args:
            specifc_pair (dict, optional): Specific pair of devices. Defaults to None.

        Returns:
            dict: Device pairing permutations.

        FOR EXAMPLE:
            Permutation 1:
            --- Box 1 --    |    --- Box 2 --
            device           |       device
              0             |         0   - proccess no. 1 (hbl_0 -> hbl_0)
              1             |         1   - proccess no. 2
              2             |         2   - proccess no. 3
              3             |         3   - proccess no. 4
            Permutation 2:
            --- Box 1 --    |    --- Box 2 --
            device           |       device
              0             |         1   - proccess no. 1 (hbl_0 -> hbl_1)
              1             |         2   - proccess no. 2
              2             |         3   - proccess no. 3
              3             |         0   - proccess no. 4
            Permutation 3:
            --- Box 1 --    |    --- Box 2 --
            device           |       device
              0             |         2   - proccess no. 1 (hbl_0 -> hbl_2)
              1             |         3   - proccess no. 2
              2             |         0   - proccess no. 3
              3             |         1   - proccess no. 4
            Permutation 3:
            --- Box 1 --    |    --- Box 2 --
            device           |       device
              0             |         3   - proccess no. 1 (hbl_0 -> hbl_3)
              1             |         0   - proccess no. 2
              2             |         1   - proccess no. 3
              3             |         2   - proccess no. 4
        """
        local_hls_info = self.get_local_hls_Info()
        remote_hls_info = self.get_remote_hls_Info()


        #Organize by cards index order
        local_org = {}
        for local_network, local_devices in local_hls_info.items():
            local_org[local_network] = sorted(local_devices, key=lambda x: (x[0], x[1]))
        remote_org = {}
        for remote_network, remote_devices in remote_hls_info.items():
            remote_org[remote_network] = sorted(remote_devices, key=lambda x: (x[0], x[1]))



        #extend organizers for unique device indexes -> ip:[ [(hbl_0, p__i), (hbl_1, p_j)], [(hbl_0, p_m), (hbl_1, p_n)] ]
        counter_map_local = {}
        extend_local_org = {}
        for local_network, local_list in local_org.items():
            counter_map_local[local_network] = {}
            extend_local_org[local_network] = []
            for local_device, local_port, local_cpu, local_gid in local_list:
                if local_device not in counter_map_local[local_network].keys():
                    counter_map_local[local_network][local_device] = 0

                list_index = counter_map_local[local_network][local_device]
                counter_map_local[local_network][local_device] += 1
                if len(extend_local_org[local_network]) == list_index:
                    extend_local_org[local_network].append([])
                extend_local_org[local_network][list_index].append((local_device, local_port, local_cpu, local_gid))

        counter_map_remote = {}
        extend_remote_org = {}
        for remote_network, remote_list in remote_org.items():
            counter_map_remote[remote_network] = {}
            extend_remote_org[remote_network] = []
            for remote_device, remote_port, remote_cpu, remote_gid in remote_list:
                if remote_device not in counter_map_remote[remote_network].keys():
                    counter_map_remote[remote_network][remote_device] = 0

                list_index = counter_map_remote[remote_network][remote_device]
                counter_map_remote[remote_network][remote_device] += 1
                if len(extend_remote_org[remote_network]) == list_index:
                    extend_remote_org[remote_network].append([])
                extend_remote_org[remote_network][list_index].append((remote_device, remote_port, remote_cpu, remote_gid))


        self.check_validaty(extend_local_org, extend_remote_org) # check same network, same unique list sizes


        res = {}
        if basic_check:
            counter = 0
            unique_network_name = ''
            for local_network, unique_local_lists in  extend_local_org.items():
                unique_remote_lists = extend_remote_org[local_network]
                for local_devices, remote_devices in zip(unique_local_lists, unique_remote_lists):
                    counter +=1
                    unique_network_name = f'{local_network}_{counter}'
                    if unique_network_name not in res.keys():
                        res[unique_network_name] = {
                            'source' : [],
                            'destination' : []
                        }
                    res[unique_network_name]['source'].append(local_devices)
                    res[unique_network_name]['destination'].append([remote_devices])
        else:
            for  local_network, unique_local_lists in  extend_local_org.items():
                unique_remote_lists = extend_remote_org[local_network]
                for local_devices in unique_local_lists:
                    for remote_devices in unique_remote_lists:
                        if local_network not in res.keys():
                            res[local_network] = {
                                'source' : [local_devices],
                                'destination' : [cyclic_iteration(remote_devices)]
                            }
                        else:
                            res[local_network]['destination'].append(cyclic_iteration(remote_devices))
        return res

    def iterate(self):
        """
        Iterates over the connections.
        """

        for network, connectivity in self.connections.items():
            self.currentNetwork = network
            self.pbar.set_description(f'Testing {network}')
            local_lists = connectivity['source']
            remote_lists = connectivity['destination']
            for local_devices in local_lists:
                for remote_cyclic_lists in remote_lists:
                    for remote_devices in remote_cyclic_lists:
                        yield local_devices, remote_devices

    def check_validaty(self, extend_local_org, extend_remote_org):
        """
        Checks the validity of the network connections.

        Args:
            extend_local_org (dict): Extended local organization.
            extend_remote_org (dict): Extended remote organization.

        Raises:
            BaseException: If the network connections are not valid.
        """
        if len(list(extend_local_org.keys())) != len(list(extend_remote_org.keys())):
            raise BaseException(f"Network amount are not equal between the two nodes : local - {len(list(extend_local_org.keys()))}, remote - {len(list(extend_remote_org.keys()))}")

        for k in  extend_local_org.keys():
            if k not in extend_remote_org.keys():
                raise BaseException(f"local network : {k} not exist in the remote node")
        for k in  extend_remote_org.keys():
            if k not in extend_local_org.keys():
                raise BaseException(f"remote network : {k} not exist in the local node")

        for local_network, local_unique_lists in extend_local_org.items():

            local_size = len(local_unique_lists[0])
            if not any((len(devices) == local_size for devices in local_unique_lists)):
                raise BaseException( \
                            f'''The nodes are not connected in one of the follwoing network topologies: N independnce networks.
                            In local network: {local_network} , exist one card that his ports are not connected to it'''\
                        )
            remote_unique_lists = extend_remote_org[local_network]
            remote_size = len(remote_unique_lists[0])
            if not any((len(devices) == remote_size for devices in remote_unique_lists)):
                raise BaseException(\
                            f'''The nodes are not connected in one of the follwoing network topologies: N independnce networks.
                            In remote network: {local_network} , exist one card that his ports are not connected to it'''\
                        )

    def getTotalIterations(self) -> int:
        """
        Gets the total number of iterations.

        Returns:
            int: Total number of iterations.
        """
        connectivity = self.connections[self.currentNetwork]

        # total_iterations = card_option_source * card_option_destination * network_options * number_of_unique_remote_lists
        total_iterations = len(connectivity['source'][0]) * len(connectivity['destination'][0]) * len(list(self.connections.keys())) * len(connectivity['destination'])
        return total_iterations

class LocalFlow(ExternalFlow):
    def __init__(self, path: str, basic_check: bool, time_stampe: str, test_type: str) -> None:
        super().__init__(path)

        self.basic_check = basic_check
        self.test_type = test_type
        self.connections = self.getExternalConnections()
        self.currentNetwork = next(iter(self.connections.keys()))
        self.dumpMetadata(time_stampe)

    def getExternalConnections(self):
        local_hls_info = self.get_local_hls_Info()


        #Organize by cards index order
        local_org = {}
        for local_network, local_devices in local_hls_info.items():
            local_org[local_network] = sorted(local_devices, key=lambda x: (x[0], x[1]))


        #extend organizers for unique device indexes -> ip:[ [(hbl_0, p__i), (hbl_1, p_j)], [(hbl_0, p_m), (hbl_1, p_n)] ]
        counter_map_local = {}
        extend_local_org = {}
        for local_network, local_list in local_org.items():
            counter_map_local[local_network] = {}
            extend_local_org[local_network] = []
            for local_device, local_port, local_cpu, local_gid in local_list:
                if local_device not in counter_map_local[local_network].keys():
                    counter_map_local[local_network][local_device] = 0

                list_index = counter_map_local[local_network][local_device]
                counter_map_local[local_network][local_device] += 1
                if len(extend_local_org[local_network]) == list_index:
                    extend_local_org[local_network].append([])
                extend_local_org[local_network][list_index].append((local_device, local_port, local_cpu, local_gid))


        self.check_validaty(extend_local_org)

        return extend_local_org

    def check_validaty(self, extend_local_org):
        if len(list(extend_local_org.keys())) == 0:
            raise BaseException('No connections found')
        for network,unique_local_lists in  extend_local_org.items():
            if len(unique_local_lists) == 0:
                raise BaseException(f'No connections found in network: {network}')
            local_size = len(unique_local_lists[0])
            if not any((len(devices) == local_size for devices in unique_local_lists)):
                raise BaseException( \
                            f'''The nodes are not connected in one of the follwoing network topologies: N independnce networks.
                            In local network: {network} , exist one card that his ports are not connected to it'''\
                        )
            for local_devices in unique_local_lists:
                card_amount = len(local_devices)
                if card_amount % 2 != 0:
                    raise BaseException( \
                            f'''Detected a odd number of cards in a given network : {network}, card amount: {card_amount}.'''\
                        )


    def getTotalIterations(self) -> int:
        """
        Gets the total number of iterations.

        Returns:
            int: Total number of iterations.
        """
        connectivity = self.connections[self.currentNetwork]
        total_iterations = 0
        if self.basic_check:
        #   total_iterations = card_option_source * card_option_destination * network_options
            total_iterations = len(connectivity)*(len(connectivity[0])//2)*len(list(self.connections.keys()))
        else:
            factor = 1
        #   total_iterations = (card_option/2)^2 * port_option^2 * network_options
            if self.test_type == 'ping_pong':
                factor = 2
            total_iterations = pow(len(connectivity[0])//2, 2) * pow(len(connectivity), 2) * len(list(self.connections.keys()))*factor
        return total_iterations

    def iterate(self):
        """
        Iterates over the connections.
        """

        if self.basic_check:
            for local_network, unique_local_lists in  self.connections.items():
                self.currentNetwork = local_network
                self.pbar.set_description(f'Testing local : {local_network}')
                for local_devices in unique_local_lists:
                        yield local_devices[:int(len(local_devices) / 2)], local_devices[int(len(local_devices) / 2):]
        else:
            for local_network, unique_local_lists in  self.connections.items():
                self.currentNetwork = local_network
                self.pbar.set_description(f'Testing local : {local_network}')
                for local_devices in unique_local_lists:
                    if self.test_type == 'ping_pong':
                        permutations = itertools.chain(getPermutations(local_devices, None))
                    else:
                        permutations = itertools.chain(getPermutationsFullDuplex(local_devices, None))

                    for permutation in permutations:
                        server_permutation = permutation['server_permutation']
                        client_permutation = permutation['client_permutation']
                        for server_list in server_permutation:
                            if len(server_list) == 0 or None in server_list:
                                continue
                            for client_lists in client_permutation:
                                for client_list in client_lists:
                                    if len(client_list) == 0 or None in client_list:
                                        continue
                                    yield server_list, client_list

    def close(self) -> None:
        pass

class InternalFlow(Flow):
    def __init__(self, test_type: str, path: str, time_stampe: str) -> None:
        super().__init__(path)
        self.__connections = None
        self.__moduleID2deviceIndex = None
        self.__device_numa_info = None
        self.__getConnectionsInternal()
        self.currentNetwork = 'internals'
        self.testType = test_type
        self.dumpMetadata(time_stampe)

    def getTotalIterations(self) -> int:
        """
        Gets the total number of iterations.

        Returns:
            int: Total number of iterations.
        """
        total = 4*7*3
        if self.testType == 'ping_pong':
            total = total*2
        return total

    def extractPortsInfo(self, shell_func):
        info = super().extractPortsInfo(shell_func)
        res = {}
        for device_index, info in info.items():
            for dev_port, ib_port, _ in info:
                if (device_index,dev_port) in res.keys():
                    raise BaseException(f'Found duplicate ib ports for the same device index and dev port: device_index = {device_index} dev_port = {dev_port} ib_ports = [{res[(device_index,dev_port)]},{ib_port}]')
                res[(device_index, dev_port)] = ib_port
        return res

    def __load_csv_mapping(self, path, portInfo):
        """
        Loads a CSV mapping file.

        Args:
            path (str): Path to the CSV file.

        Returns:
            dict: Mapping dictionary.
        """
        mapping = {}
        with open(path, 'r') as file:
            lines = file.readlines()
        for line in lines:
            if line.startswith('#'):
                continue
            parts = line.strip().split('\t')

            source_moduleID = int(parts[0])
            source_deviceIndex = self.__moduleID2deviceIndex[source_moduleID]
            source_port = int(parts[1])
            if (source_deviceIndex, source_port) not in portInfo.keys():
                raise BaseException(f'Port info not found for device index: {source_deviceIndex} and port: {source_port}, port info: {portInfo}')
            source_ib_port = portInfo[(source_deviceIndex, source_port)]
            destination_moduleID = int(parts[2])
            destination_port = int(parts[3])
            destination_deviceIndex = self.__moduleID2deviceIndex[destination_moduleID]
            if (destination_deviceIndex, destination_port) not in portInfo.keys():
                raise BaseException(f'Port info not found for device index: {destination_deviceIndex} and port: {destination_port}, port info: {portInfo}')
            destination_ib_port = portInfo[(destination_deviceIndex, destination_port)]
            key = (source_moduleID, destination_moduleID)
            if key not in mapping.keys():
                mapping[key] = []
            mapping[key].append((source_ib_port, destination_ib_port))


        return mapping

    def iterate(self):
        """
        Iterates over the connections.
        """
        self.pbar.set_description(f'Testing internals nics')
        moduleIds = list(range(0, 8))
        if self.testType == 'ping_pong':
            permutations = itertools.chain(getPermutations(moduleIds, -1))
        else:
            permutations = itertools.chain(getPermutationsFullDuplex(moduleIds, -1))

        for permutation in permutations:
            client_permutation = permutation['client_permutation']
            while not len(client_permutation[0]) == 0:
                source_list = [ [] for _ in range(len(next(iter(self.__connections.values()))))]
                destination_list = [ [] for _ in range(len(next(iter(self.__connections.values()))))]
                for index, server_list in enumerate(permutation['server_permutation']):
                    clients = client_permutation[index].pop(0)
                    for source, destination in zip(server_list, clients):
                        if source == -1 or destination == -1:
                            continue
                        for i in range(len(self.__connections[(source, destination)])):
                            source_port, destination_port = self.__connections[(source, destination)][i]
                            source_list[i].append((self.__moduleID2deviceIndex[source], source_port, self.__device_numa_info[self.__moduleID2deviceIndex[source]], [0])) #device_ib, device_port, device_cpu, device_gid
                            destination_list[i].append((self.__moduleID2deviceIndex[destination], destination_port, self.__device_numa_info[self.__moduleID2deviceIndex[destination]], [0])) #device_ib, device_port, device_cpu, device_gid
                for i in range(len(source_list)):
                    yield source_list[i], destination_list[i]

    def __getdeviceIndexMapping(self, shell_func):
        """
        Gets the device index mapping.

        Args:
            shell_func (function): Function to execute shell commands.

        Returns:
            dict: Device index mapping.
        """
        info = shell_func('hl-smi -Q module_id,index -f csv,noheader')
        res = {}
        for line in info:
            module_id, index = line.strip().split(',')
            res[int(module_id)] = int(index.strip())
        return res

    def __getConnectionsInternal(self):
        """
        Gets the connections.

        Returns:
            dict: Connections.
        """
        serverInternalConnectivityPath = os.getenv('SERVER_INTERNAL_CONNECTIVITY_PATH')
        if serverInternalConnectivityPath == None:
            raise BaseException(f'SERVER_INTERNAL_CONNECTIVITY_PATH variable is not defined, please assign to it the path of the internal connectivity file (take a look at the README.md)')
        self.__moduleID2deviceIndex = self.__getdeviceIndexMapping(shell_func=executeSubProc)
        ports_info = self.extractPortsInfo(shell_func=executeSubProc)
        self.__connections  = self.__load_csv_mapping(f'{serverInternalConnectivityPath}', ports_info)
        setup_numa_info = self.get_numa_info(shell_func=executeSubProc)
        self.__device_numa_info = self.extractDeviceNumaInfo(setup_numa_info, shell_func=executeSubProc)

class PerfTest(Suite):
    def __init__(self, args) -> None:
        """
        Initializes the PerfTest class.

        Args:
            args: Arguments for the performance test.
        """
        super().__init__(device=None, server_hostname=args.server_hostname, client_hostname=args.client_hostname, test_type=args.test_type)

        self.specificTitle = 'PerfTest'
        self.titleConfig = {'rx_depth': args.rx_depth, 'iters': args.iters, 'size': args.size}
        self.criteria = args.criteria if hasattr(args,'criteria') else -1
        if self.criteria != -1:
            self.titleConfig['criteria'] = self.criteria
        if args.basic_check:
            self.titleConfig['basic_check'] = args.basic_check
        self.output_path = args.output
        self.at_least_one_failed = False
        self.__currentPath = executeSubProc('pwd')[0]
        if self.client_host_name != None:
            self.flow = RemoteFlow(self.client_ip, args.ssh_port, args.ssh_key_file, args.known_hosts_file, self.__currentPath, args.basic_check, args.time_stampe)
        elif args.test_local:
            self.flow = LocalFlow(self.__currentPath, args.basic_check, args.time_stampe, args.test_type)
        else:
            self.flow = InternalFlow(self.test_type, self.__currentPath, args.time_stampe)

        chk = args.chk if hasattr(args,'chk') else False
        self.test_dict = {
            'ping_pong' : perf_ping_pong(client_host_name=self.client_host_name,
                                         client_ip=self.client_ip,
                                         server_host_name=self.server_host_name,
                                         server_ip=self.server_ip,
                                         tcp_port=args.tcp_port,
                                         current_path=self.__currentPath,
                                         rx_depth=str(args.rx_depth),
                                         iters=str(args.iters),
                                         size=str(args.size),
                                         chk=chk),
            'write_lat' : perf_write_lat(client_host_name=self.client_host_name,
                                         client_ip=self.client_ip,
                                         server_host_name=self.server_host_name,
                                         server_ip=self.server_ip,
                                         tcp_port=args.tcp_port,
                                         current_path=self.__currentPath,
                                         rx_depth=str(args.rx_depth),
                                         iters=str(args.iters),
                                         size=str(args.size)),
            'write_bw' : perf_write_bw(client_host_name=self.client_host_name,
                                       client_ip=self.client_ip,
                                        server_host_name=self.server_host_name,
                                        server_ip=self.server_ip,
                                        tcp_port=args.tcp_port,
                                        current_path=self.__currentPath,
                                        rx_depth=str(args.rx_depth),
                                        iters=str(args.iters),
                                        size=str(args.size))
        }

    def __create_artifacts(self):
        """
        Creates artifacts for the performance test.

        Returns:
            str: Output directory path.
        """
        # Get the current time
        current_time = time.localtime()
        formatted_time = time.strftime("%Y-%m-%d::%H:%M:%S", current_time)
        if len(self.output_path) != 0:
            self.report_name = f"{self.output_path}/scaleUpReport_{formatted_time}.txt"
            createDirectory(self.output_path)
        else:
            self.report_name = f"scaleUpReport_{formatted_time}.txt"
        report =  open(self.report_name, "w")
        self.printHeader(report)
        report.close()
        print_('The Results:', self.report_name)
        if len(self.output_path) != 0:
            output_directory_root = self.output_path
        else:
            output_directory_root = '.'
        output_directory = output_directory_root + '/perftest_result'
        self.logs_dir_path = output_directory
        if os.path.isdir(output_directory):
            shutil.rmtree(output_directory)
        return output_directory

    def __add2summary(self, que, summary, network):
        """
        Adds the test results to the summary.

        Args:
            que (multiprocessing.Queue): Queue containing the test results.
            summary (dict): Summary dictionary to store the results.
            network (str): Network name.
        """
        server_return_code, client_return_code, server_result, client_result, c_ib_dev, c_ib_port, r_ib_dev, r_ib_port = que.get()
        msg = ''
        if server_return_code == None or client_return_code == None:
            msg = f'{c_ib_dev}:{c_ib_port}->{r_ib_dev}:{r_ib_port} :: ERROR - connection failed'
            print_(msg, self.report_name)
            summary[network]['Error']['counter'] += 1
            summary[network]['Error']['connections'].append('* '+msg)
            summary[network]['Total']['counter'] += 1
            self.at_least_one_failed = True
            return
        if server_return_code != 0 or client_return_code != 0:
            self.at_least_one_failed = True
        if server_return_code == 100 or client_return_code == 100:
            msg = f'{c_ib_dev}:{c_ib_port}->{r_ib_dev}:{r_ib_port} :: TIMEOUT ({server_return_code}, {client_return_code}) -  Check toggeling ports'
            print_(msg, self.report_name)
            summary[network]['Timeout']['counter'] += 1
            summary[network]['Timeout']['connections'].append('* '+msg)
        elif server_return_code == 1 or client_return_code == 1:
            msg = f'{c_ib_dev}:{c_ib_port}->{r_ib_dev}:{r_ib_port} :: ERROR ({server_return_code}, {client_return_code})'
            print_(msg, self.report_name)
            summary[network]['Error']['counter'] += 1
            summary[network]['Error']['connections'].append('* '+msg)
        elif server_return_code in [2, 3] or client_return_code in [2, 3]:
            msg = f'{c_ib_dev}:{c_ib_port}->{r_ib_dev}:{r_ib_port} :: ERROR ({server_return_code}, {client_return_code}) - lost Gaudi connection'
            print_(msg, self.report_name)
            summary[network]['Error']['counter'] += 1
            summary[network]['Error']['connections'].append('* '+msg)
        elif (client_result and self.criteria>0 and not client_result.checkCriteria(self.criteria)) \
                or \
             (server_result and self.criteria>0 and not server_result.checkCriteria(self.criteria)):
            msg = f'{c_ib_dev}:{c_ib_port}->{r_ib_dev}:{r_ib_port} :: FAILED ({server_return_code}, {client_return_code}) - SERVER({server_result}), CLIENT({client_result}) , CRITERIA({self.criteria})'
            print_(msg, self.report_name)
            summary[network]['Failed']['counter'] += 1
            summary[network]['Failed']['connections'].append('* '+msg)
            self.at_least_one_failed = True
        elif server_return_code > 1 or client_return_code > 1:
            msg = f'{c_ib_dev}:{c_ib_port}->{r_ib_dev}:{r_ib_port} :: FAILED ({server_return_code}, {client_return_code})'
            print_(msg, self.report_name)
            summary[network]['Failed']['counter'] += 1
            summary[network]['Failed']['connections'].append('* '+msg)
        elif server_return_code == 0 and client_return_code == 0:
            if (server_result == None or client_result == None):
                 msg = f'{c_ib_dev}:{c_ib_port}->{r_ib_dev}:{r_ib_port} :: PASSED'
            elif(server_result and client_result and self.criteria>0 and server_result.checkCriteria(self.criteria) and client_result.checkCriteria(self.criteria)):
                msg = f'{c_ib_dev}:{c_ib_port}->{r_ib_dev}:{r_ib_port} :: PASSED ({server_return_code}, {client_return_code}) - SERVER({server_result}), CLIENT({client_result}) , CRITERIA({self.criteria})'
            else:
                msg = f'{c_ib_dev}:{c_ib_port}->{r_ib_dev}:{r_ib_port} :: Client({client_result}), Server({server_result})'
            print_(msg, self.report_name)
            summary[network]['Passed']['counter'] += 1
        else:
            msg = f'{c_ib_dev}:{c_ib_port}->{r_ib_dev}:{r_ib_port} :: UNKNOWN ({server_return_code}, {client_return_code})'
            print_(msg, self.report_name)
            summary[network]['Unknown']['counter'] += 1
            summary[network]['Unknown']['connections'].append('* '+msg)
        summary[network]['Total']['counter'] += 1

    def __init_network_dict(self):
        """
        Initializes the network dictionary.

        Returns:
            dict: Initialized network dictionary.
        """
        return  {
                    'Time': {
                        'start': time.perf_counter(),
                        'end': None
                    },
                    'Total' : {
                        'counter' : 0
                    },
                    'Passed' : {
                        'counter' : 0
                    },
                    'Failed' : {
                        'counter' : 0,
                        'connections': []
                    },
                    'Error'  : {
                        'counter' : 0,
                        'connections': []
                    },
                    'Timeout'  : {
                        'counter' : 0,
                        'connections': []
                    },
                    'Unknown'  : {
                        'counter' : 0,
                        'connections': []
                    }
                }

    def __print_summary(self, summary):
        """
        Prints the summary of the performance test.

        Args:
            summary (dict): Summary dictionary containing the test results.
        """
        print_(f'\n\n**********************', self.report_name)
        print_(f'*      Summary       *', self.report_name)
        print_(f'**********************', self.report_name)
        for network, info in summary.items():
            print_(f"Network: {network} (duration: {(info['Time']['end'] - info['Time']['start']):.3f} seconds)", self.report_name)
            if info['Passed']['counter']>0:
                print_(f"Passed: {info['Passed']['counter']}", self.report_name)
            if info['Failed']['counter']>0:
                print_(f"Failed: {info['Failed']['counter']}", self.report_name)
            if info['Error']['counter']>0:
                print_(f"Error: {info['Error']['counter']}", self.report_name)
            if info['Timeout']['counter']>0:
                print_(f"Timeout: {info['Timeout']['counter']}", self.report_name)
            if info['Unknown']['counter']>0:
                print_(f"Unknown: {info['Unknown']['counter']}", self.report_name)
            if info['Total']['counter']>0:
                print_(f"Total: {info['Total']['counter']}", self.report_name)
            if info['Failed']['counter']>0:
                print_('\n'.join(info['Failed']['connections']), self.report_name)
            if info['Error']['counter']>0:
                print_('\n'.join(info['Error']['connections']), self.report_name)
            if info['Unknown']['counter']>0:
                print_('\n'.join(info['Unknown']['connections']), self.report_name)
            if info['Timeout']['counter']>0:
                print_('\n'.join(info['Timeout']['connections']), self.report_name)

    def apply(self) -> None:
        """
        Applies the performance test by executing the test and updating the summary.
        """
        output_directory_root = self.__create_artifacts()
        self.printHeader()
        summary = {}
        if self.test_dict != None:
            test = self.test_dict[self.test_type]
            test.printHeader()
            print('\n')

            previous_network = self.flow.getCurrentNetwork()
            summary[previous_network] = self.__init_network_dict()
            print_(f'\n$ {previous_network} $', self.report_name)
            with tqdm(total=self.flow.getTotalIterations()) as pbar:
                self.flow.setPbar(pbar)
                self.__ipc = []
                for local_devices, remote_devices in self.flow.iterate():
                    if previous_network != self.flow.getCurrentNetwork():
                        previous_network = self.flow.getCurrentNetwork()
                        summary[previous_network] = self.__init_network_dict()
                        print_(f'\n$ {previous_network} $', self.report_name)
                    for local_device,remote_device  in zip(local_devices, remote_devices):
                        c_ib_dev, c_ib_port, c_cpu, c_gid = local_device
                        r_ib_dev, r_ib_port, r_cpu, r_gid = remote_device
                        c_ib_dev = f'hbl_{c_ib_dev}'
                        r_ib_dev = f'hbl_{r_ib_dev}'
                        output_directory = f'{output_directory_root}/{c_ib_dev}/{c_ib_port}/{r_ib_dev}'
                        createDirectory(output_directory)
                        q = multiprocessing.Queue()
                        p = multiprocessing.Process(target=job, args=(q, test, self.flow.getSSHArgs(), output_directory, c_ib_dev, c_ib_port, c_cpu, c_gid, r_ib_dev, r_ib_port, r_cpu, r_gid))
                        p.start()
                        self.__ipc.append((p,q))
                    for proc, que in self.__ipc:
                        self.__add2summary(que, summary, self.flow.getCurrentNetwork())
                        pbar.update(1)
                        proc.join(timeout=60)
                        if proc.is_alive():
                            proc.terminate()
                            proc.join()
                    self.__ipc.clear()

                    summary[previous_network]['Time']['end'] = time.perf_counter()

        self.__print_summary(summary)
        return
