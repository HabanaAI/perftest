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
Main Entry Point for Habana Performance Testing Tool.

This module serves as the primary entry point for the Habana performance testing
framework. It coordinates test suite execution, environment configuration, and
provides the command-line interface for performance testing operations.

Key Features:
- Command-line argument parsing and validation
- Environment variable loading from configuration files
- Test suite factory pattern for different test types
- Error handling and graceful shutdown
- Integration with performance profiling tools

Supported Test Suites:
- perftest: Network performance testing suite

Functions:
    suiteFactory: Creates appropriate test suite instances based on user selection
    main: Main execution function handling setup, execution, and cleanup
"""

import argparse
#import cProfile
import os
from suite import PerfTest
from common_args import add_common_args

def suiteFactory(test_suite, args):
    """
    Factory function to create test suite instances.
    
    This function implements the factory pattern to instantiate the appropriate
    test suite class based on the user's selection. It provides a clean interface
    for adding new test suites in the future.
    
    Args:
        test_suite (str): Name of the test suite to create ("perftest")
        args: Configuration arguments containing test parameters
        
    Returns:
        Suite: Instance of the requested test suite class
        
    Raises:
        ValueError: If an unsupported test suite name is provided
        
    Note:
        Currently supports only "perftest" suite, but designed for extensibility.
    """
    if test_suite == "perftest":
        return PerfTest(args)

def main(args):
    """
    Main execution function for the performance testing tool.
    
    This function orchestrates the complete test execution lifecycle:
    1. Loads environment variables from configuration files
    2. Initializes the appropriate test suite
    3. Executes tests with optional profiling
    4. Handles cleanup and error reporting
    
    Args:
        args: Parsed command-line arguments containing test configuration
        
    Returns:
        int: Exit code (0 for success, 1 for failure)
        
    Note:
        - Loads environment variables from ~/.ENV_SCALEUP if present
        - Supports optional performance profiling (currently commented out)
        - Ensures proper cleanup even if tests fail
    """

    variables = []
    env_file_path = f'{os.environ["HOME"]}/.ENV_SCALEUP'
    if os.path.exists(env_file_path):
        with open(env_file_path, 'r') as file:
            # Read all lines into a list and strip newline characters
            variables = [line.strip() for line in file]
    for var in variables:
        var = var.split('=')
        os.environ[var[0]] = var[1]
    test_suite = args.suite
    suite = None
    try:
        #profiler = cProfile.Profile()
        #profiler.enable()

        # Choose testSuit: perfTest, fabTest
        suite = suiteFactory(test_suite, args)

        #profiler.disable()
        #profiler.dump_stats(f'{os.environ["HOME"]}/.scaleup_profiler')

        suite.apply()
    finally:
        if suite != None:
            suite.close()
    if suite.at_least_one_failed:
        return 12
    return 0



if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='One-Direction Testing Tool')

    parser.add_argument('-sn', '--server_hostname',required=True, metavar='<current-host-name>',\
                        type=str,\
                        help="Server hostname")
    parser.add_argument('-cn', '--client_hostname',required=False, default="", metavar='<remote-host-name>',\
                        type=str,\
                        help="client hostname")
    parser.add_argument('-sp','--ssh_port', type=int, default=22, metavar='',\
                                help='specify SSH port to use (default: %(default)s)')
    parser.add_argument('-ts','--time_stampe', type=str, metavar='',\
                                help='specify time stampe for the test')
    perftest_parser = add_common_args(parser)

    args= parser.parse_args()

    if args.client_hostname == "" and not args.internal and not args.test_local:
        raise BaseException("-cn/--client_hostname is required")

    exit(main(args))