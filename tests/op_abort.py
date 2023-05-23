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

from utils.test_suite import CapTPTestCase
from utils.captp_types import OpAbort, OpBootstrap, DescImportObject


class OpBootstrapTest(CapTPTestCase):
    """ `op:abort` - end a session through aborting """

    def test_abort_before_setup(self):
        """ Aborting a session before a session has been fully setup """
        # Lets then abort the session and then send our `op:start-session`
        abort_op = OpAbort("test-abort-before-setup")
        self.remote.send_message(abort_op)

        # Now setup the session
        self.remote.setup_session()

        # Finally see if we can use the setup session by sending an `op:bootstrap`
        bootstrap_op = OpBootstrap(0, DescImportObject(0))
        with self.assertRaises((TimeoutError, ConnectionAbortedError)):
            self.remote.expect_message_to(bootstrap_op.exported_resolve_me_desc, timeout=10)

    def test_abort_after_setup(self):
        """ Aborting a session after setup renders it unusable """
        self.remote.setup_session()

        # Lets then abort the session and then send our `op:start-session`
        abort_op = OpAbort("test-abort-after-setup")
        self.remote.send_message(abort_op)

        # Finally see if we can use the setup session by sending an `op:bootstrap`
        bootstrap_op = OpBootstrap(0, DescImportObject(0))
        with self.assertRaises((TimeoutError, ConnectionAbortedError)):
            self.remote.expect_message_to(bootstrap_op.exported_resolve_me_desc, timeout=10)
