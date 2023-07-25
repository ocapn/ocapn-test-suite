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

from contrib.syrup import Symbol
from utils.test_suite import CapTPTestCase, retry_on_network_timeout
from utils.captp_types import OpBootstrap, OpDeliver, OpDeliverOnly, DescImportObject


class OpBootstrapTest(CapTPTestCase):
    """ `op:bootstrap` - fetching the bootstrap object """

    @retry_on_network_timeout
    def test_op_bootstrap(self):
        """ Check we can fetch the bootstrap object """
        self.remote.setup_session(self.captp_version)

        bootstrap_op = OpBootstrap(0, self.remote.next_import_object)
        self.remote.send_message(bootstrap_op)

        # Wait for a message to the resolve-me-desc we specified.
        response = self.remote.expect_message_to(bootstrap_op.exported_resolve_me_desc)
        self.assertIsInstance(response, (OpDeliver, OpDeliverOnly))

        # Check it's fulfilling the promise with a `desc:import-object`.
        self.assertEqual(response.args[0], Symbol("fulfill"))
        self.assertIsInstance(response.args[1], DescImportObject)
