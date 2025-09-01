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
Common Command-Line Arguments Module for Habana Performance Testing.

This module provides a centralized location for defining common command-line
arguments used across different components of the Habana performance testing
framework. It ensures consistency in argument parsing and provides a unified
interface for test configuration.

Key Features:
- Centralized argument definition for consistency across tools
- Support for multiple test types (ping-pong, bandwidth, latency)
- SSH configuration and authentication parameters
- Network testing mode selection (internal, external, local)
- Comprehensive test parameter configuration
- Pass/fail criteria specification for automated testing

Functions:
    add_common_args: Add common command-line arguments to an argument parser

Supported Test Types:
    - ping_pong: Network ping-pong latency testing
    - write_bw: Network bandwidth measurement
    - write_lat: Network latency measurement

Network Testing Modes:
    - External: Tests between different hosts via external network
    - Internal: Tests within hosts using internal network interfaces
    - Local: Tests all internal routes between devices in a server
"""

import argparse
import os

def add_common_args(parser):
    """
    Add common arguments to the parser.

    Args:
        parser (argparse.ArgumentParser): The argument parser to which the common arguments will be added.

    Returns:
        argparse.ArgumentParser: The parser with the added common arguments.
    """
    os.environ['COLUMNS'] = '200'
    parser.add_argument('-skf', '--ssh_key_file', metavar='',\
                        type=str,\
                        help="ssh private key file path")
    parser.add_argument('-khf', '--known_hosts_file', metavar='', type=str, default='~/.ssh/known_hosts',\
                        help="custom SSH known hosts file path (default: %(default)s)")
    parser.add_argument('-o', '--output', metavar='', type=str, required=True, help="save all the log files in a specific path (the folder must be exist)")

    suite_parsers = parser.add_subparsers(dest='suite')

    perftest_parser = suite_parsers.add_parser('perftest', help='Habana performance suite test', formatter_class=argparse.RawTextHelpFormatter)

    perftest_parser.add_argument('-tp','--tcp_port', type=int, default=1100, metavar='',\
                                help='specify the TCP port range script will use, for example: --tcp_port 1100 -> [1100,1107] (default: %(default)s)')
    perftest_parser.add_argument('-int','--internal',action='store_true', default=False , help='Enable internal nic testing (supported tests: write_bw and ping_pong)')
    perftest_parser.add_argument('-dis_rem_ext_tes','--disable_remote_external_test',action='store_true', default=False , help='disable remote external nic testing')
    perftest_parser.add_argument('-bc','--basic_check',action='store_true', default=False , help='basic check will test port 0 with port 0, port 1 with port 1, etc')
    perftest_parser.add_argument('-tl','--test_local',action='store_true', default=False , help='test local will test all the internal routes between Gaudis in a server - external nics')

    test_parser = perftest_parser.add_subparsers(dest='test_type')


    pp_parser = test_parser.add_parser('ping_pong', help='Ping-Pong test', formatter_class=argparse.RawTextHelpFormatter)
    bw_parser = test_parser.add_parser('write_bw', help='Bandwidth test', formatter_class=argparse.RawTextHelpFormatter)
    lat_parser = test_parser.add_parser('write_lat', help='Latency test', formatter_class=argparse.RawTextHelpFormatter)

    ############ PING-PONG ########################
    pp_parser.add_argument('-s','--size', type=int, default=4096, metavar='',\
                                help='size of message to exchange (default: %(default)s)')
    pp_parser.add_argument('-r','--rx_depth', type=int, default=128, metavar='',\
                                help='number of receives to post at a time (default: %(default)s)')
    pp_parser.add_argument('-n','--iters', type=int, default=10, metavar='',\
                                help='number of exchanges (default: %(default)s)')
    pp_parser.add_argument('-c','--chk', action='store_true', default=False,\
                                help='validate received buffer')
    ############ LATENCY ########################
    lat_parser.add_argument('-s','--size', type=int, default=1024, metavar='',\
                                help='size of message to exchange (default: %(default)s)')
    lat_parser.add_argument('-r','--rx_depth', type=int, default=128, metavar='',\
                                help='number of receives to post at a time (default: %(default)s)')
    lat_parser.add_argument('-n','--iters', type=int, default=500000, metavar='',\
                                help='number of exchanges (default: %(default)s)')
    lat_parser.add_argument('-c','--criteria', type=int, default=-1, metavar='',\
                                help='pass/fail criteria value for thresholding the test, the value unit will be microseconds (default: not used)')
    ############ BANDWIDTH ########################
    bw_parser.add_argument('-s','--size', type=int, default=1048576, metavar='',\
                                help='size of message to exchange (default: %(default)s)')
    bw_parser.add_argument('-r','--rx_depth', type=int, default=128, metavar='',\
                                help='number of receives to post at a time (default: %(default)s)')
    bw_parser.add_argument('-n','--iters', type=int, default=100000, metavar='',\
                                help='number of exchanges (default: %(default)s)')
    bw_parser.add_argument('-c','--criteria', type=int, default=-1, metavar='',\
                                help='pass/fail criteria value for thresholding the test, the value unit will be Gbps (default: not used)')


    return perftest_parser