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
from utils.test_suite import CapTPTestCase

class OPStartSession(CapTPTestCase):
    """ `op:start-session` - used to begin the CapTP session """

    def test_captp_remote_version(self):
        """ Remote CapTP session sends a valid `op:start-session` """
        op = self.netlayer.receive_message()
        self.assertEqual(op.label, Symbol("op:start-session"))
        self.assertEqual(len(op.args), 4)

        captp_version, encoded_pubkey, encoded_location, encoded_location_sig = op.args
        # TODO: Enable when the spec transitions from drafts to published.
        #self.assertEqual(captp_version, "1")
        pubkey = self._captp_to_key_pair(encoded_pubkey)
        location_sig = self._captp_to_signature(encoded_location_sig)

        # Wrap the location in the my-location record
        location = Record(label=Symbol("my-location"), args=(encoded_location,))

        # This raises an exception if the signature is invalid
        self.assertIsNone(pubkey.verify(location_sig, syrup_encode(location)))
    
    def test_start_session_with_invalid_version(self):
        """ Remote CapTP session aborts upon invalid version """
        # First wait for their `op:start-session` message.
        self.netlayer.receive_message()

        # Then send our own `op:start-session` message with an invalid version.
        pubkey, privkey = self._generate_key()
        location = self.netlayer.location
        location_sig = privkey.sign(syrup_encode(location))
        start_session_op = Record(
            label=Symbol("op:start-session"),
            args=[
                "invalid-version-number",
                self._key_pair_to_captp(pubkey),
                location,
                self._signature_to_captp(location_sig)
            ]
        )
        self.netlayer.send_message(start_session_op)

        # We should receive an abort message from the remote.
        expected_abort = self.netlayer.receive_message()
        self.assertEqual(expected_abort.label, Symbol("op:abort"))
    
    def test_start_session_with_invalid_signature(self):
        """ Remote CapTP session aborts upon invalid location signature """
        # First wait for their `op:start-session` message.
        remote_start_session = self.netlayer.receive_message()

        # Then send our own `op:start-session` message with an invalid signature.
        pubkey, privkey = self._generate_key()
        location = self.netlayer.location
        invalid_location_sig = privkey.sign(b"i am invalid")
        start_session_op = Record(
            label=Symbol("op:start-session"),
            args=[
                remote_start_session.args[0],
                self._key_pair_to_captp(pubkey),
                location,
                self._signature_to_captp(invalid_location_sig)
            ]
        )
        self.netlayer.send_message(start_session_op)

        # We should receive an abort message from the remote.
        expected_abort = self.netlayer.receive_message()
        self.assertEqual(expected_abort.label, Symbol("op:abort"))
