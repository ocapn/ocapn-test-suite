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
import time
import hashlib

from contrib.syrup import Symbol, Record, syrup_encode
from utils import captp_types
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class CapTPSession:
    """ Representation of a CapTP session for testing purposes """

    def __init__(self, connection, location, is_outbound):
        self.connection = connection
        self.location = location
        self.is_outbound = is_outbound
        self._bootstrap_object = None
        self.public_key = None
        self.private_key = None
        self.remote_public_key = None

        self._next_import_position = 0
        self._next_answer_position = 0
        self._next_handoff_count = 0

        self.remote_seen_handoff_counts = set()

    def setup_session(self, captp_version):
        """ Sets up the session by sending a `op:start-sesion` and verifying theirs """
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = captp_types.CapTPPublicKey.from_private_key(self.private_key)

        # Create the signature.
        encoded_my_location = syrup_encode(Record(
            label=Symbol("my-location"),
            args=[self.location.to_syrup_record()]
        ))
        location_sig = self.private_key.sign(encoded_my_location)
        start_session_op = captp_types.OpStartSession(
            self.captp_version,
            self.public_key,
            self.location,
            location_sig
        )

        if self.is_outbound:
            self.send_message(start_session_op)
            # Get their `op:start-session` message
            remote_start_session = self.receive_message()
            assert isinstance(remote_start_session, captp_types.OpStartSession)
        else:
            # Get their `op:start-session` message
            remote_start_session = self.receive_message()
            assert isinstance(remote_start_session, captp_types.OpStartSession)
            start_session_op.captp_version = remote_start_session.captp_version

        self.remote_public_key = remote_start_session.session_pubkey


        # Get their `op:start-session` message
        remote_start_session = self.receive_message()
        assert isinstance(remote_start_session, captp_types.OpStartSession)
        self.remote_public_key = remote_start_session.session_pubkey

    def close(self):
        """ Aborts the connection and closes the socket """
        self.send_message(captp_types.OpAbort("shutdown"))
        self._bootstrap_object = None
        self.connection.close()

    def send_message(self, msg):
        """ Send a message to the remote """
        self.connection.send_message(msg)

    def receive_message(self, timeout=60):
        """ Receive a message from the remote """
        msg = self.connection.receive_message(timeout=timeout)

        # Find out if the message is a deliver which may contain a handoff receive
        # If it is, we should keep track of the handoff counts we've seen so far.
        if not isinstance(msg, captp_types.OpDeliver):
            return msg

        for arg in msg.args:
            if not isinstance(arg, captp_types.DescSigEnvelope):
                continue
            if not isinstance(arg.object, captp_types.DescHandoffReceive):
                continue

            # Found one.
            handoff_receive = arg.object
            if handoff_receive.handoff_count in self.remote_seen_handoff_counts:
                raise Exception("Received a handoff count we've already seen")
            self.remote_seen_handoff_counts.add(handoff_receive.handoff_count)

        return msg

    @property
    def our_side_id(self):
        our_encoded_pubkey = self.public_key.to_syrup()
        single_hashed_id = hashlib.sha256(our_encoded_pubkey).digest()
        return hashlib.sha256(single_hashed_id).digest()

    @property
    def their_side_id(self):
        their_encoded_pubkey = self.remote_public_key.to_syrup()
        single_hashed_id = hashlib.sha256(their_encoded_pubkey).digest()
        return hashlib.sha256(single_hashed_id).digest()

    @property
    def id(self):
        """ The session ID is a unique identifier for the session derived from each parties session keys """
        # Calculate the ID of each side
        our_side_id = self.our_side_id
        their_side_id = self.their_side_id

        # 2. Sort them based on the resulting octets
        keys = [our_side_id, their_side_id]
        keys.sort()

        # 3. Concatinating them in the order from number 3
        session_id_hash = keys[0] + keys[1]

        # 4. Append the string "prot0" to the beginning
        session_id_hash = b"prot0" + session_id_hash

        # 5. SHA256 hash the resulting string, this is the `session-ID`
        hashed_session_id = hashlib.sha256(session_id_hash).digest()

        # 6. SHA256 hash of the result produced in step 6.
        return hashlib.sha256(hashed_session_id).digest()

    @property
    def next_import_object(self) -> captp_types.DescImportObject:
        """ Returns the next object position """
        position = self._next_import_position
        self._next_import_position += 1
        return captp_types.DescImportObject(position)

    @property
    def next_answer(self) -> captp_types.DescAnswer:
        """ Returns the next answer position """
        position = self._next_answer_position
        self._next_answer_position += 1
        return captp_types.DescAnswer(position)

    @property
    def next_handoff_count(self) -> int:
        """ Returns the next handoff count """
        count = self._next_handoff_count
        self._next_handoff_count += 1
        return count

    def get_bootstrap_object(self, pipeline=False):
        """" Gets the bootstrap object from the remote session """
        if self._bootstrap_object is not None:
            return self._bootstrap_object

        bootstrap_op = captp_types.OpBootstrap(self.next_answer.position, self.next_import_object)
        self.send_message(bootstrap_op)
        if pipeline:
            # Note: If pipelining is usd, the bootstrap object won't actually
            # get cached as we're wanting to cache the resolved object, not the
            # promise.
            return captp_types.DescAnswer(bootstrap_op.answer_position)

        export_desc = bootstrap_op.resolve_me_desc.to_desc_export()
        message = self.expect_message_to(export_desc)
        assert message.args[0] == Symbol("fulfill")
        assert isinstance(message.args[1], captp_types.DescImportObject)
        self._bootstrap_object = message.args[1].to_desc_export()
        return self._bootstrap_object

    def fetch_object(self, swiss_num, pipeline=False):
        """ Fetches an object from the remote bootstrap object """
        bootstrap_object = self.get_bootstrap_object(pipeline=pipeline)
        fetch_msg = captp_types.OpDeliver(
            to=bootstrap_object,
            args=[Symbol("fetch"), swiss_num],
            answer_position=self.next_answer.position if pipeline else False,
            resolve_me_desc=self.next_import_object
        )
        self.send_message(fetch_msg)
        if pipeline:
            return fetch_msg.vow

        response = self.expect_promise_resolution(fetch_msg.exported_resolve_me_desc)
        assert response.args[0] == Symbol("fulfill")
        fetched_object = response.args[1]
        assert isinstance(fetched_object, captp_types.DescImportObject)
        return fetched_object.to_desc_export()

    def expect_message_type(self, message_type, timeout=60):
        """ Reads messages until one of the given type is received """
        while timeout >= 0:
            start_time = time.time()
            message = self.receive_message(timeout=timeout)
            end_time = time.time()
            timeout -= end_time - start_time

            if isinstance(message, message_type):
                return message

    def expect_message_to(self, recipients, timeout=60):
        """ Reads messages until one is sent to the given recipient """
        if isinstance(recipients, (captp_types.DescAnswer, captp_types.DescExport)):
            recipients = [recipients]

        while timeout >= 0:
            start_time = time.time()
            message = self.expect_message_type((captp_types.OpDeliver, captp_types.OpDeliverOnly), timeout=timeout)
            end_time = time.time()
            timeout -= end_time - start_time

            # The `recipient` can be a tuple of matches, or a single match
            # the recipient can also be a DescExport or DescAnswer
            for recipient in recipients:
                if message.to == recipient:
                    return message

    def expect_promise_resolution(self, resolve_me_desc: captp_types.DescExport, timeout=60):
        """ Reads until a promise resolves to a non-promise value """
        while timeout >= 0:
            start_time = time.time()
            message = self.expect_message_to(resolve_me_desc, timeout=timeout)
            end_time = time.time()
            timeout -= end_time - start_time

            # Check it's a fulfill
            assert message.args[0] in [Symbol("fulfill"), Symbol("break")]

            # If the promise has broken, return that.
            if message.args[0] == Symbol("break"):
                return message

            # If the resolution is another promise, keep going
            if isinstance(message.args[1], captp_types.DescImportPromise):
                # Now we have to construct a listen message to get the answer
                # from the promise provided to us.
                listen_op = captp_types.OpListen(
                    message.args[1].as_export,
                    self.next_import_object,
                    wants_partial=True
                )
                self.send_message(listen_op)
                resolve_me_desc = listen_op.exported_resolve_me_desc
                continue

            return message
