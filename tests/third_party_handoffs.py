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

import hashlib
import random
import string

from contrib.syrup import syrup_encode, Symbol
from utils.test_suite import CapTPTestCase
from utils.ocapn_uris import OCapNMachine, OCapNSturdyref
from utils import captp_types

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class HandoffTestCase(CapTPTestCase):
    """ CapTP test case with two netlayer instances for testing handoffs """

    def setUp(self) -> None:
        super().setUp()
        self.other_netlayer = self._create_new_netlayer()

    def _create_new_netlayer(self):
        netlayer_class = type(self.netlayer)
        return netlayer_class()

    def _generate_two_keypairs(self):
        """ Generate two keypairs to represent those of a session between two machines """
        machine_a_private_key = Ed25519PrivateKey.generate()
        machine_b_private_key = Ed25519PrivateKey.generate()

        machine_a_public_key = captp_types.CapTPPublicKey(machine_a_private_key.public_key())
        machine_b_public_key = captp_types.CapTPPublicKey(machine_b_private_key.public_key())

        return machine_a_public_key, machine_a_private_key, machine_b_public_key, machine_b_private_key


class HandoffRemoteAsReciever(HandoffTestCase):
    """ Third party Handoffs: Receiver """

    def setUp(self, *args, **kwargs):
        super().setUp(*args, **kwargs)

        # Create a gifter and exporter sessions
        self.g2r_session = self.remote
        self.g2r_session.setup_session()

        # Get the greeter
        self.g2r_greeter = self.g2r_session.fetch_object(b"VMDDd1voKWarCe2GvgLbxbVFysNzRPzx")

        # Since we're both the gifter and exporter, let's just mimic a connection
        self.g2e_pubkey, self.g2e_privkey, self.e2g_pubkey, self.e2g_privkey = self._generate_two_keypairs()

    def make_valid_handoff(self, gift_id=b"my-gift"):
        # This isn't how real IDs are generated, but it's good enough for testing
        gifter_exporter_session_id = hashlib.sha256(b"Gifter <-> exporter session ID").digest()
        gifter_side_id = hashlib.sha256(b"Gifter side ID").digest()

        # Make the handoff give
        handoff_give = captp_types.DescHandoffGive(
            self.g2r_session.remote_public_key,
            self.other_netlayer.location,
            gifter_exporter_session_id,
            gifter_side_id,
            gift_id
        )
        return captp_types.DescSigEnvelope(
            handoff_give,
            self.g2e_privkey.sign(syrup_encode(handoff_give.to_syrup()))
        )

    def test_valid_handoff_without_prior_connection(self):
        """ Valid handoff give without prior connection """
        signed_handoff_give = self.make_valid_handoff()
        handoff_give = signed_handoff_give.object

        # Send a message to the gifter with the handoff give
        deliver_msg = captp_types.OpDeliverOnly(
            self.g2r_greeter,
            [signed_handoff_give]
        )
        self.g2r_session.send_message(deliver_msg)

        # The receiver should connect to us
        self.e2r_session = self.other_netlayer.accept()
        self.e2r_session.setup_session()

        # The receiver should then create their own desc:handoff-receive and connect to the exporter
        # Lets get their bootstrap object and give them ours.
        their_bootstrap_op = self.e2r_session.expect_message_type(captp_types.OpBootstrap)
        our_bootstrap_refr = self.e2r_session.next_import_object
        bootstrap_reply_msg = captp_types.OpDeliverOnly(
            their_bootstrap_op.exported_resolve_me_desc,
            [Symbol("fulfill"), our_bootstrap_refr]
        )
        self.e2r_session.send_message(bootstrap_reply_msg)

        # The receiver should then message us with the desc:handoff-receive
        their_withdraw_gift_msg = self.e2r_session.expect_message_to(
            (our_bootstrap_refr.to_desc_export(), their_bootstrap_op.vow)
        )
        self.assertEqual(their_withdraw_gift_msg.args[0], Symbol("withdraw-gift"))

        # Check we've got a signed handoff receive, with a valid signature
        signed_handoff_receive = their_withdraw_gift_msg.args[1]
        self.assertIsInstance(signed_handoff_receive, captp_types.DescSigEnvelope)
        self.assertIsInstance(signed_handoff_receive.object, captp_types.DescHandoffReceive)

        # Check the handoff receive is valid
        handoff_receive = signed_handoff_receive.object
        self.assertEqual(handoff_receive.signed_give.object, handoff_give)

        # We actually already have access to this because we are the gifter, but
        # for good measure, lets get it off the handoff-give like we normally would
        r2g_pubkey = handoff_receive.signed_give.object.receiver_key
        self.assertTrue(signed_handoff_receive.verify(r2g_pubkey))

        # Check the session ID is what we expect it to be
        self.assertEqual(handoff_receive.receiving_session, self.g2r_session.id)

    def test_valid_handoff_with_prior_connection(self):
        """ Valid handoff-give, with prior connection """
        signed_handoff_give = self.make_valid_handoff()
        handoff_give = signed_handoff_give.object

        # Send a message to the greeter with our handoff give.
        deliver_msg = captp_types.OpDeliverOnly(
            self.g2r_greeter,
            [signed_handoff_give]
        )
        self.g2r_session.send_message(deliver_msg)

        # The receiver should connect to us
        self.e2r_session = self.other_netlayer.accept()
        self.e2r_session.setup_session()

        # The receiver should then create their own desc:handoff-receive and connect to the exporter
        # Lets get their bootstrap object and give them ours.
        their_bootstrap_op = self.e2r_session.expect_message_type(captp_types.OpBootstrap)
        our_bootstrap_refr = self.e2r_session.next_import_object
        bootstrap_reply_msg = captp_types.OpDeliverOnly(
            their_bootstrap_op.exported_resolve_me_desc,
            [Symbol("fulfill"), our_bootstrap_refr]
        )
        self.e2r_session.send_message(bootstrap_reply_msg)

        # The receiver should then message us with the desc:handoff-receive
        their_withdraw_gift_msg = self.e2r_session.expect_message_to(
            (our_bootstrap_refr.to_desc_export(), their_bootstrap_op.vow)
        )
        self.assertEqual(their_withdraw_gift_msg.args[0], Symbol("withdraw-gift"))

        # Check we've got a signed handoff receive, with a valid signature
        signed_handoff_receive = their_withdraw_gift_msg.args[1]
        self.assertIsInstance(signed_handoff_receive, captp_types.DescSigEnvelope)
        self.assertIsInstance(signed_handoff_receive.object, captp_types.DescHandoffReceive)

        # Check the handoff receive is valid
        handoff_receive = signed_handoff_receive.object
        self.assertEqual(handoff_receive.signed_give.object, handoff_give)

        # We actually already have access to this because we are the gifter, but
        # for good measure, lets get it off the handoff-give like we normally would
        r2g_pubkey = handoff_receive.signed_give.object.receiver_key
        self.assertTrue(signed_handoff_receive.verify(r2g_pubkey))

        # Check the session ID is what we expect it to be
        self.assertEqual(handoff_receive.receiving_session, self.g2r_session.id)


class HandoffRemoteAsExporter(HandoffTestCase):
    """ Third party handoffs: Exporter """

    def setUp(self, *args, **kwargs):
        super().setUp(*args, **kwargs)

        # Create a gifter and exporter sessions
        self.g2e_session = self.remote
        self.g2e_session.setup_session()
        self.r2e_session = self.other_netlayer.connect(self.ocapn_uri)
        self.r2e_session.setup_session()

        # Since we're both the gifter and exporter, let's just mimic a connection
        self.g2r_pubkey, self.g2r_privkey, self.r2g_pubkey, self.r2g_privkey = self._generate_two_keypairs()

        # Get the greeter
        self.g2e_greeter_refr = self.g2e_session.fetch_object(b"VMDDd1voKWarCe2GvgLbxbVFysNzRPzx")

    def make_valid_handoff(self, gift_id=b"my-gift"):
        handoff_give = captp_types.DescHandoffGive(
            self.r2g_pubkey,
            self.ocapn_uri,
            self.g2e_session.id,
            self.g2e_session.our_side_id,
            gift_id
        )
        signed_handoff_give = captp_types.DescSigEnvelope(
            handoff_give,
            self.g2e_session.private_key.sign(syrup_encode(handoff_give.to_syrup()))
        )

        return signed_handoff_give

    def make_valid_handoff_receive(self, signed_handoff_give, handoff_count=0):
        handoff_receive = captp_types.DescHandoffReceive(
            self.r2e_session.id,
            self.r2e_session.our_side_id,
            handoff_count,
            signed_handoff_give
        )
        return captp_types.DescSigEnvelope(
            handoff_receive,
            self.r2g_privkey.sign(syrup_encode(handoff_receive.to_syrup()))
        )

    def test_valid_handoff(self):
        """ Valid handoff receive, gift already deposited """
        signed_handoff_give = self.make_valid_handoff()
        handoff_give = signed_handoff_give.object

        # Deposit the gift with the exporter
        deposit_gift_msg = captp_types.OpDeliverOnly(
            self.g2e_session.get_bootstrap_object(),
            [Symbol("deposit-gift"), handoff_give.gift_id, self.g2e_greeter_refr]
        )
        self.g2e_session.send_message(deposit_gift_msg)

        # Withdraw the gift from the exporter
        signed_handoff_receive = self.make_valid_handoff_receive(signed_handoff_give)
        withdraw_gift_msg = captp_types.OpDeliver(
            self.r2e_session.get_bootstrap_object(),
            [Symbol("withdraw-gift"), signed_handoff_receive],
            False,
            self.r2e_session.next_import_object
        )
        self.r2e_session.send_message(withdraw_gift_msg)

        resolved_handoff = self.r2e_session.expect_promise_resolution(withdraw_gift_msg.exported_resolve_me_desc)
        self.assertEqual(resolved_handoff.args[0], Symbol("fulfill"))
        self.assertIsInstance(resolved_handoff.args[1], captp_types.DescImportObject)

    def test_valid_handoff_wait_deposit_gift(self):
        """ Valid handoff receive, sending deposite gift later """
        signed_handoff_give = self.make_valid_handoff()
        handoff_give = signed_handoff_give.object

        # Withdraw the gift from the exporter
        signed_handoff_receive = self.make_valid_handoff_receive(signed_handoff_give)
        withdraw_gift_msg = captp_types.OpDeliver(
            self.r2e_session.get_bootstrap_object(),
            [Symbol("withdraw-gift"), signed_handoff_receive],
            False,
            self.r2e_session.next_import_object
        )
        self.r2e_session.send_message(withdraw_gift_msg)

        # Send the deposit gift message and wait for a promise to the gifted object
        resolved_handoff_vow = self.r2e_session.expect_message_to(withdraw_gift_msg.exported_resolve_me_desc)
        self.assertEqual(resolved_handoff_vow.args[0], Symbol("fulfill"))
        self.assertIsInstance(resolved_handoff_vow.args[1], captp_types.DescImportPromise)

        # Deposit the gift with the exporter
        deposit_gift_msg = captp_types.OpDeliverOnly(
            self.g2e_session.get_bootstrap_object(),
            [Symbol("deposit-gift"), handoff_give.gift_id, self.g2e_greeter_refr]
        )
        self.g2e_session.send_message(deposit_gift_msg)

        # Send `op:listen` to get notified for the handoff vow resolution
        listen_on_vow_msg = captp_types.OpListen(
            resolved_handoff_vow.args[1].to_desc_export(),
            self.r2e_session.next_import_object,
            True
        )
        self.r2e_session.send_message(listen_on_vow_msg)

        resolved_handoff = self.r2e_session.expect_promise_resolution(listen_on_vow_msg.exported_resolve_me_desc)
        self.assertEqual(resolved_handoff.args[0], Symbol("fulfill"))
        self.assertIsInstance(resolved_handoff.args[1], captp_types.DescImportObject)

    def test_handoff_receive_invalid_handoff_count(self):
        """ Reject handoff-receive with invalid (already used) handoff count """
        signed_handoff_give = self.make_valid_handoff()
        handoff_give = signed_handoff_give.object

        # Deposit the gift with the exporter
        deposit_gift_msg = captp_types.OpDeliverOnly(
            self.g2e_session.get_bootstrap_object(),
            [Symbol("deposit-gift"), handoff_give.gift_id, self.g2e_greeter_refr]
        )
        self.g2e_session.send_message(deposit_gift_msg)

        # Withdraw the gift from the exporter (first time)
        signed_handoff_receive = self.make_valid_handoff_receive(signed_handoff_give)
        withdraw_gift_msg = captp_types.OpDeliver(
            self.r2e_session.get_bootstrap_object(),
            [Symbol("withdraw-gift"), signed_handoff_receive],
            False,
            self.r2e_session.next_import_object
        )
        self.r2e_session.send_message(withdraw_gift_msg)

        # Check that the handoff was successful (so far, so normal)
        resolved_handoff = self.r2e_session.expect_promise_resolution(withdraw_gift_msg.exported_resolve_me_desc)
        self.assertEqual(resolved_handoff.args[0], Symbol("fulfill"))
        self.assertIsInstance(resolved_handoff.args[1], captp_types.DescImportObject)

        # Now lets try and withdraw the gift again, with the same handoff count, this MUST fail
        # we need to deposit the gift again, so we can withdraw it again
        withdraw_gift_msg.resolve_me_desc = self.r2e_session.next_import_object
        self.g2e_session.send_message(deposit_gift_msg)
        self.r2e_session.send_message(withdraw_gift_msg)

        failed_handoff = self.r2e_session.expect_promise_resolution(withdraw_gift_msg.exported_resolve_me_desc)
        self.assertEqual(failed_handoff.args[0], Symbol("break"))

    def test_handoff_receive_invalid_signature(self):
        """ Reject handoff-receive with invalid signature """
        signed_handoff_give = self.make_valid_handoff()
        handoff_give = signed_handoff_give.object

        # Deposit the gift with the exporter
        deposit_gift_msg = captp_types.OpDeliverOnly(
            self.g2e_session.get_bootstrap_object(),
            [Symbol("deposit-gift"), handoff_give.gift_id, self.g2e_greeter_refr]
        )
        self.g2e_session.send_message(deposit_gift_msg)

        # Withdraw the gift from the exporter (first time)
        signed_handoff_receive = self.make_valid_handoff_receive(signed_handoff_give)

        # Change the certificate to be invalid
        signed_handoff_receive.signature = self.g2r_privkey.sign(b"this signature is invalid")
        withdraw_gift_msg = captp_types.OpDeliver(
            self.r2e_session.get_bootstrap_object(),
            [Symbol("withdraw-gift"), signed_handoff_receive],
            False,
            self.r2e_session.next_import_object
        )
        self.r2e_session.send_message(withdraw_gift_msg)

        # Check that we didn't get a successful handoff.
        resolved_handoff = self.r2e_session.expect_promise_resolution(withdraw_gift_msg.exported_resolve_me_desc)
        self.assertEqual(resolved_handoff.args[0], Symbol("break"))
