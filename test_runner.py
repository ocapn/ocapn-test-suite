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

from utils.locators import Locator
from utils.test_suite import CapTPTestRunner
from netlayers.onion import OnionNetlayer


def setup_netlayer(locator):
    """ Setup the netlayer for the provided locator """
    if locator.transport == "onion":
        return OnionNetlayer(locator)
    else:
        raise ValueError(f"Unsupported transport layer: {locator.transport}")

if __name__ == "__main__":
    # Support a command line argument which MUST be provided to run the tests
    # this argument should take an address and validate it.
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "locator",
        help="OCapN Machine locator to test against"
    )
    args = parser.parse_args()

    # Parse and validate the address
    locator = Locator(args.locator)
    if not locator.validate():
        print(f"OCapN machine location is invalid: {locator}")
        sys.exit(1)

    try:
        netlayer = setup_netlayer(locator)
    except ImportError as e:
        print(f"Unable to setup netlayer: {e}")
        sys.exit(1)

    runner = CapTPTestRunner(netlayer)
    suite = runner.loadTests()
    runner.run(suite)
