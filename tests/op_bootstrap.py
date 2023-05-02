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

import unittest

from contrib.syrup import Record, Symbol, syrup_encode
from utils.test_suite import CompleteCapTPTestCase

class OpBootstrap(CompleteCapTPTestCase):
    """ `op:bootstrap` - fetching the bootstrap object """

    def test_op_bootstrap(self):
        """ Check we can fetch the bootstrap object """
        # Ask for the bootstrap object to be exported at position 0
        # And for us to get a resolution message back at position 0.
        bootstrap_op = Record(
            Symbol("op:bootstrap"),
            (0, Record(Symbol("desc:import-object"), (0,)))
        )
        self.netlayer.send_message(bootstrap_op)

        # Wait for the resolution message, it could be the other implementation
        # sends other messages such as `op:bootstrap` to us, ignore those.
        response = self.expect_message(Symbol("op:deliver-only"))
        if response is None:
            raise Exception("op:bootstrap promise was never fulfilled")

        # Check it's to the desc:import-object we specified.
        self.assertTrue(isinstance(response.args[0], Record))
        self.assertEqual(response.args[0].label, Symbol("desc:export"))
        self.assertEqual(response.args[0].args[0], 0)
        
        message_args = response.args[1]
        self.assertEqual(message_args[0], Symbol("fulfill"))
        self.assertTrue(isinstance(message_args[1], Record))
        self.assertEqual(message_args[1].label, Symbol("desc:import-object"))
        self.assertEqual(type(message_args[1].args[0]), int)