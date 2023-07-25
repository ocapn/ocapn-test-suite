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

from contrib.syrup import syrup_encode, Record, Symbol
from utils.test_suite import CapTPTestCase, retry_on_network_timeout
from utils.captp_types import OpStartSession, OpAbort, CapTPPublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class OpStartSessionTest(CapTPTestCase):
    """ `op:start-session` - used to begin the CapTP session """

    @retry_on_network_timeout
    def test_captp_remote_version(self):
        """ Remote CapTP session sends a valid `op:start-session` """
        private_key = Ed25519PrivateKey.generate()
        public_key = CapTPPublicKey.from_private_key(private_key)
        location = self.netlayer.location
        location_sig = private_key.sign(
            syrup_encode(Record(Symbol("my-location"), [location.to_syrup_record()]))
        )
        start_session_op = OpStartSession(
            self.captp_version,
            public_key,
            location,
            location_sig
        )
        self.remote.send_message(start_session_op)

        remote_start_session = self.remote.receive_message()
        self.assertIsInstance(remote_start_session, OpStartSession)
        self.assertEqual(remote_start_session.captp_version, self.captp_version)

    @retry_on_network_timeout
    def test_start_session_with_invalid_version(self):
        """ Remote CapTP session aborts upon invalid version """
        # Send our own `op:start-session` message with an invalid version.
        private_key = Ed25519PrivateKey.generate()
        public_key = CapTPPublicKey.from_private_key(private_key)
        location = self.netlayer.location
        location_sig = private_key.sign(
            syrup_encode(Record(Symbol("my-location"), [location.to_syrup_record()]))
        )
        start_session_op = OpStartSession(
            "invalid-version-number",
            public_key,
            location,
            location_sig
        )
        self.remote.send_message(start_session_op)

        # We should receive an abort message from the remote.
        expected_abort = self.remote.receive_message()
        self.assertIsInstance(expected_abort, OpAbort)

    @retry_on_network_timeout
    def test_start_session_with_invalid_signature(self):
        """ Remote CapTP session aborts upon invalid location signature """
        # Send our own `op:start-session` message with an invalid signature.
        private_key = Ed25519PrivateKey.generate()
        public_key = CapTPPublicKey.from_private_key(private_key)
        location = self.netlayer.location
        invalid_location_sig = private_key.sign(b"i am invalid")
        start_session_op = OpStartSession(
            self.captp_version,
            public_key,
            location,
            invalid_location_sig
        )
        self.remote.send_message(start_session_op)

        # We should receive an abort message from the remote.
        expected_abort = self.remote.receive_message()
        self.assertIsInstance(expected_abort, OpAbort)
