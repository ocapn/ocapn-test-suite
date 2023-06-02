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

from contrib.syrup import syrup_encode, Symbol
from utils.test_suite import CapTPTestCase
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
    """ Third party handoffs where the remote implementation is the reciever """

    def test_valid_handoff_without_prior_connection(self):
        """ The remote recieves a valid handoff-give and performs the handoff correctly to a new session """
        gifter_session = self.remote
        gifter_session.setup_session()
        greeter_refr = gifter_session.fetch_object(b"VMDDd1voKWarCe2GvgLbxbVFysNzRPzx")

        # Create a keypair for the gifter <-> exporter session
        g2e_pubkey, g2e_privkey, e2g_pubkey, e2g_privkey = self._generate_two_keypairs()
        gifter_exporter_id = hashlib.sha256(b"foobar").digest()

        # We will be performing a handoff by sending the "greeter" a reference
        # to an object in the `exporter_session`.
        handoff_give = captp_types.DescHandoffGive(
            gifter_session.remote_public_key,
            self.other_netlayer.location,
            gifter_exporter_id,
            g2e_pubkey,
            b"my-gift"
        )
        signed_handoff_give = captp_types.DescSigEnvelope(
            handoff_give,
            g2e_privkey.sign(syrup_encode(handoff_give.to_syrup()))
        )
        deliver_msg = captp_types.OpDeliverOnly(
            greeter_refr,
            [signed_handoff_give]
        )
        gifter_session.send_message(deliver_msg)

        # The receiver should then create their own desc:handoff-receive and connect to the exporter
        exporter_session = self.other_netlayer.accept()
        exporter_session.setup_session()
        their_bootstrap_op = exporter_session.expect_message_type(captp_types.OpBootstrap)
        our_bootstrap_refr = exporter_session.next_import_object
        bootstrap_reply_msg = captp_types.OpDeliverOnly(
            their_bootstrap_op.exported_resolve_me_desc,
            [Symbol("fulfill"), our_bootstrap_refr]
        )
        exporter_session.send_message(bootstrap_reply_msg)

        # The receiver should then message us with the desc:handoff-receive
        their_withdraw_gift_msg = exporter_session.expect_message_to(
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

        # FIXME: We should check the reciever side, but it's broken.
        # We actually already have access to this because we are the gifter, but
        # for good measure, lets get it off the handoff-give like we normally would
        r2g_pubkey = handoff_receive.signed_give.object.receiver_key
        self.assertTrue(signed_handoff_receive.verify(r2g_pubkey))

        # Check the session ID is what we expect it to be
        # FIXME: Needs fixing in the spec, it says this should be the exporter_session
        self.assertEqual(handoff_receive.receiving_session, gifter_session.id)
    
    # def test_valid_handoff_with_prior_connection(self):
    #     """ The remote recieves a valid handoff-give and performs the handoff correctly to an already existing session """
    #     gifter_session = self.remote
    #     gifter_session.setup_session()
    #     greeter_refr = gifter_session.fetch_object(b"VMDDd1voKWarCe2GvgLbxbVFysNzRPzx")
        
    #     # Setup a session between the reciever and the exporter
    #     exporter_session = self.other_netlayer.connect(self.ocapn_uri)
    #     exporter_session.setup_session()

    #     # Create a keypair for the gifter <-> exporter session
    #     g2e_pubkey, g2e_privkey, e2g_pubkey, e2g_privkey = self._generate_two_keypairs()
    #     gifter_exporter_id = hashlib.sha256(b"foobar").digest()

    #     # We will be performing a handoff by sending the "greeter" a reference
    #     # to an object in the `exporter_session`.
    #     handoff_give = captp_types.DescHandoffGive(
    #         gifter_session.remote_public_key,
    #         self.other_netlayer.location,
    #         gifter_exporter_id,
    #         g2e_pubkey,
    #         b"my-gift"
    #     )
    #     signed_handoff_give = captp_types.DescSigEnvelope(
    #         handoff_give,
    #         g2e_privkey.sign(syrup_encode(handoff_give.to_syrup()))
    #     )
    #     deliver_msg = captp_types.OpDeliverOnly(
    #         greeter_refr,
    #         [signed_handoff_give]
    #     )
    #     gifter_session.send_message(deliver_msg)

    #     # They should be sending their `op:bootstrap` now in order to withdraw the gift
    #     their_bootstrap_op = exporter_session.expect_message_type(captp_types.OpBootstrap)
    #     our_bootstrap_refr = exporter_session.next_import_object
    #     bootstrap_reply_msg = captp_types.OpDeliverOnly(
    #         their_bootstrap_op.exported_resolve_me_desc,
    #         [Symbol("fulfill"), our_bootstrap_refr]
    #     )
    #     exporter_session.send_message(bootstrap_reply_msg)

    #     # The receiver should then message us with the desc:handoff-receive
    #     their_withdraw_gift_msg = exporter_session.expect_message_to(
    #         (our_bootstrap_refr.to_desc_export(), their_bootstrap_op.vow)
    #     )
    #     self.assertEqual(their_withdraw_gift_msg.args[0], Symbol("withdraw-gift"))

    #     # Check we've got a signed handoff receive, with a valid signature
    #     signed_handoff_receive = their_withdraw_gift_msg.args[1]
    #     self.assertIsInstance(signed_handoff_receive, captp_types.DescSigEnvelope)
    #     self.assertIsInstance(signed_handoff_receive.object, captp_types.DescHandoffReceive)

    #     # Check the handoff receive is valid
    #     handoff_receive = signed_handoff_receive.object
    #     self.assertEqual(handoff_receive.signed_give.object, handoff_give)

    #     # FIXME: We should check the reciever side, but it's broken.
    #     # We actually already have access to this because we are the gifter, but
    #     # for good measure, lets get it off the handoff-give like we normally would
    #     r2g_pubkey = handoff_receive.signed_give.object.receiver_key
    #     self.assertTrue(signed_handoff_receive.verify(r2g_pubkey))

    #     # Check the session ID is what we expect it to be
    #     # FIXME: Needs fixing in the spec, it says this should be the exporter_session
    #     self.assertEqual(handoff_receive.receiving_session, gifter_session.id)
