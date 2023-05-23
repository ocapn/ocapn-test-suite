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

from contrib.syrup import Symbol, Record, syrup_encode
from utils import captp_types
from utils.cryptography import Crypto


class CapTPSession(Crypto):
    """ Representation of a CapTP session for testing purposes """

    def __init__(self, connection, location):
        self.connection = connection
        self.location = location
        self._imports = {}
        self._exports = {}
        self._gifts = {}
        self._bootstrap_object = None

        self._next_import_position = 0
        self._next_answer_position = 0

    def setup_session(self):
        """ Sets up the session by sending a `op:start-sesion` and verifying theirs """
        # Get their `op:start-session` message
        remote_start_session = self.receive_message()
        assert isinstance(remote_start_session, captp_types.OpStartSession)

        pubkey, privkey = self._generate_key()
        location = self.location

        # Create the signature.
        my_location = Record(
            label=Symbol("my-location"),
            args=[location.to_syrup_record()]
        )
        location_sig = privkey.sign(syrup_encode(my_location))
        start_session_op = captp_types.OpStartSession(
            remote_start_session.captp_version,
            pubkey,
            location,
            location_sig
        )
        self.send_message(start_session_op)

    def close(self):
        """ Aborts the connection and closes the socket """
        self.send_message(captp_types.OpAbort("shutdown"))
        self._imports = {}
        self._exports = {}
        self._gifts = {}
        self._bootstrap_object = None
        self.connection.close()

    def send_message(self, msg):
        """ Send a message to the remote """
        self.connection.send_message(msg)

    def receive_message(self, timeout=60):
        """ Receive a message from the remote """
        return self.connection.receive_message(timeout=timeout)

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

    def expect_message_to(self, recipient: captp_types.DescExport, timeout=60):
        """ Reads messages until one is sent to the given recipient """

        while timeout >= 0:
            start_time = time.time()
            message = self.receive_message(timeout=timeout)
            end_time = time.time()
            timeout -= end_time - start_time

            # Skip messages which aren't deliver or deliver-only
            if not isinstance(message, (captp_types.OpDeliver, captp_types.OpDeliverOnly)):
                continue

            # If the message is to the recipient, return it
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
                    wants_partial=False
                )
                self.send_message(listen_op)
                resolve_me_desc = listen_op.exported_resolve_me_desc
                continue

            return message
