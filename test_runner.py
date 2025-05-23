# Copyright 2023 Jessica Tallon
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import sys
from urllib.parse import urlparse

from contrib.syrup import Symbol
from utils.ocapn_uris import OCapNNode
from utils.test_suite import CapTPTestRunner
from netlayers.onion import OnionNetlayer
from netlayers.testing_only_tcp import TestingOnlyTCPNetlayer


def setup_netlayer(ocapn_node):
    """ Setup the netlayer for the provided OCapN node """
    if ocapn_node.transport == Symbol("onion"):
        return OnionNetlayer()
    elif ocapn_node.transport == Symbol("tcp-testing-only"):
        url = urlparse(f"tcp-testing-only://{ocapn_node.address}")
        if url.port is None:
            raise Exception("All tcp-testing-only URIs require a port")
        else:
            return TestingOnlyTCPNetlayer(url.hostname)
    else:
        raise ValueError(f"Unsupported transport layer: {ocapn_node.transport}")


if __name__ == "__main__":
    # Support a command line argument which MUST be provided to run the tests
    # this argument should take an address and validate it.
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "locator",
        help="OCapN Node locator to test against"
    )
    parser.add_argument(
        "--test-module",
        help="Specific test module to run",
        default=None
    )
    parser.add_argument(
        "--captp-version",
        help="Override the CapTP version sent by the test suite",
        default="1.0"
    )
    parser.add_argument(
        "-v",
        "--verbose",
        help="More verbose test printing",
        default=False,
        action="store_true"
    )
    args = parser.parse_args()

    # Parse and validate the address
    ocapn_node_uri = OCapNNode.from_uri(args.locator)

    try:
        netlayer = setup_netlayer(ocapn_node_uri)
    except ImportError as e:
        print(f"Unable to setup netlayer: {e}")
        sys.exit(1)

    verbosity = 2 if args.verbose else 1

    runner = CapTPTestRunner(netlayer, ocapn_node_uri, args.captp_version, verbosity=verbosity)
    suite = runner.loadTests(args.test_module)
    result = runner.run(suite)

    if not result.wasSuccessful():
        sys.exit(1)
