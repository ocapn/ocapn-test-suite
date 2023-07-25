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
from utils import ocapn_uris
from utils.test_suite import CapTPTestCase, retry_on_network_timeout
from utils.captp_types import OpStartSession, OpAbort, CapTPPublicKey, OpDeliverOnly
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

    @retry_on_network_timeout
    def test_crossed_hellos_mitigation_aborts_inbound(self):
        """ Crossed Hellos Problem is detected: inbound connection aborts """
        # To cause the remote side to try to open a session with us, we'll need to
        # use the "sturdyref enlivener" and get them to make a session to another
        # session we control, where we can make an outbound session to them at the
        # same time.

        # Setup our session to the the remote side.
        self.remote.setup_session()

        # Get the the sturdyref enlivener actor
        sturdyref_enlivener_refr = self.remote.fetch_object(b"gi02I1qghIwPiKGKleCQAOhpy3ZtYRpB")

        # Setup other session to try a crossed hellos and create a sturdyref to it.
        netlayer_class = type(self.netlayer)
        other_session = netlayer_class()
        sturdyref = ocapn_uris.OCapNSturdyref(other_session.location, b"my-object")

        # Send the message getting the other session to enliven it.
        msg = OpDeliverOnly(sturdyref_enlivener_refr, [sturdyref.to_syrup_record()])
        self.remote.send_message(msg)

        # Get the location and create a signature
        location = other_session.location
        encoded_location_sig = syrup_encode(Record(
            Symbol("my-location"),
            [location.to_syrup_record()]
        ))

        # Wait for our inbound connection
        inbound = other_session.accept()
        inbound.private_key = Ed25519PrivateKey.generate()
        inbound.public_key = CapTPPublicKey.from_private_key(inbound.private_key)
        inbound_remote_start_session = inbound.expect_message_type(OpStartSession)
        inbound.remote_public_key = inbound_remote_start_session.session_pubkey

        outbound = other_session.connect(self.ocapn_uri)
        # We need to keep generating a key until we find one where the outbound session
        # would win out.
        while True:
            outbound.private_key = Ed25519PrivateKey.generate()
            outbound.public_key = CapTPPublicKey.from_private_key(outbound.private_key)
            ids = [outbound.our_side_id, inbound.their_side_id]
            ids.sort()
            if ids[0] == inbound.their_side_id:
                break

        outbound_location_sig = Record(
            Symbol("my-location"),
            [outbound.location.to_syrup_record()]
        )
        outbound_start_session_op = OpStartSession(
            self.captp_version,
            outbound.public_key,
            outbound.location,
            outbound.private_key.sign(syrup_encode(outbound_location_sig))
        )
        outbound.send_message(outbound_start_session_op)

        maybe_abort = inbound.expect_message_type(OpAbort)
        self.assertIsInstance(maybe_abort, OpAbort)

    @retry_on_network_timeout
    def test_crossed_hellos_mitigation_outbound_aborts(self):
        """ Crossed Hellos Problem is detected: outbound connection aborts """
        # To cause the remote side to try to open a session with us, we'll need to
        # use the "sturdyref enlivener" and get them to make a session to another
        # session we control, where we can make an outbound session to them at the
        # same time.

        # Setup our session to the the remote side.
        self.remote.setup_session()

        # Get the the sturdyref enlivener actor
        sturdyref_enlivener_refr = self.remote.fetch_object(b"gi02I1qghIwPiKGKleCQAOhpy3ZtYRpB")

        # Setup other session to try a crossed hellos and create a sturdyref to it.
        netlayer_class = type(self.netlayer)
        other_session = netlayer_class()
        sturdyref = ocapn_uris.OCapNSturdyref(other_session.location, b"my-object")

        # Send the message getting the other session to enliven it.
        msg = OpDeliverOnly(sturdyref_enlivener_refr, [sturdyref.to_syrup_record()])
        self.remote.send_message(msg)

        # Get the location and create a signature
        location = other_session.location
        encoded_location_sig = syrup_encode(Record(
            Symbol("my-location"),
            [location.to_syrup_record()]
        ))

        # Wait for our inbound connection
        inbound = other_session.accept()
        inbound.private_key = Ed25519PrivateKey.generate()
        inbound.public_key = CapTPPublicKey.from_private_key(inbound.private_key)
        inbound_remote_start_session = inbound.expect_message_type(OpStartSession)
        inbound.remote_public_key = inbound_remote_start_session.session_pubkey

        outbound = other_session.connect(self.ocapn_uri)
        # We need to keep generating a key until we find one where the outbound session
        # would win out.
        while True:
            outbound.private_key = Ed25519PrivateKey.generate()
            outbound.public_key = CapTPPublicKey.from_private_key(outbound.private_key)
            ids = [outbound.our_side_id, inbound.their_side_id]
            ids.sort()
            if ids[0] == outbound.our_side_id:
                break

        outbound_location_sig = Record(
            Symbol("my-location"),
            [outbound.location.to_syrup_record()]
        )
        outbound_start_session_op = OpStartSession(
            inbound_remote_start_session.captp_version,
            outbound.public_key,
            outbound.location,
            outbound.private_key.sign(syrup_encode(outbound_location_sig))
        )
        outbound.send_message(outbound_start_session_op)

        maybe_abort = outbound.expect_message_type(OpAbort)
        self.assertIsInstance(maybe_abort, OpAbort)
