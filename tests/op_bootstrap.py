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
        # Get an import-object for the resolve-me-desc and send a bootstrap
        # object asking for it to be available at answer position `0`.
        resolve_me_desc = self._next_import_object
        bootstrap_op = Record(
            Symbol("op:bootstrap"),
            [0, resolve_me_desc]
        )
        self.netlayer.send_message(bootstrap_op)

        # Wait for a message to the resolve-me-desc we specified.
        exported_resolve_me_desc = self._import_object_to_export(resolve_me_desc)
        response = self._expect_message_to(exported_resolve_me_desc)
        if not isinstance(response, Record):
            raise Exception("op:bootstrap promise was never fulfilled")

        # Check it's fulfilling the promise with a `desc:import-object`.
        message_args = response.args[1]
        self.assertEqual(message_args[0], Symbol("fulfill"))
        self.assertTrue(isinstance(message_args[1], Record))
        self.assertEqual(message_args[1].label, Symbol("desc:import-object"))
        self.assertEqual(type(message_args[1].args[0]), int)