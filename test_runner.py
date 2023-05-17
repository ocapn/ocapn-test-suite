## Copyright 2023 Jessica Tallon
##
## Licensed under the Apache License, Version 2.0 (the "License");
## you may not use this file except in compliance with the License.
## You may obtain a copy of the License at
##
##     http://www.apache.org/licenses/LICENSE-2.0
##
## Unless required by applicable law or agreed to in writing, software
## distributed under the License is distributed on an "AS IS" BASIS,
## WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
## See the License for the specific language governing permissions and
## limitations under the License.

import argparse
import unittest
import sys

from contrib.syrup import Symbol
from utils.ocapn_uris import OCapNMachine
from utils.test_suite import CapTPTestRunner
from netlayers.onion import OnionNetlayer


def setup_netlayer(ocapn_machine):
    """ Setup the netlayer for the provided OCapN machine """
    if ocapn_machine.transport == Symbol("onion"):
        return OnionNetlayer()
    else:
        raise ValueError(f"Unsupported transport layer: {ocapn_machine.transport}")

if __name__ == "__main__":
    # Support a command line argument which MUST be provided to run the tests
    # this argument should take an address and validate it.
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "locator",
        help="OCapN Machine locator to test against"
    )
    parser.add_argument(
        "--test-module",
        help="Specific test module to run",
        default=None
    )
    args = parser.parse_args()

    # Parse and validate the address
    ocapn_machine_uri = OCapNMachine.from_uri(args.locator)

    try:
        netlayer = setup_netlayer(ocapn_machine_uri)
    except ImportError as e:
        print(f"Unable to setup netlayer: {e}")
        sys.exit(1)

    runner = CapTPTestRunner(netlayer, ocapn_machine_uri)
    suite = runner.loadTests(args.test_module)
    runner.run(suite)
