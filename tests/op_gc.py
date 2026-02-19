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

from contrib.syrup import Symbol
from utils.test_suite import CapTPTestCase, retry_on_network_timeout
from utils.captp_types import OpGcExport, OpGcAnswer, OpDeliver

class GCTestCase(CapTPTestCase):

    @retry_on_network_timeout
    def setUp(self, *args, **kwargs):
        # These represent the wire_delta provided to us by the other side.
        self.gc_exports = {}
        self.gc_answers = set()

    def _handle_gc_message(self, timeout=30):
        while timeout > 0:
            start_time = time.time()
            msg = self.remote.expect_message_type((OpGcExport, OpGcAnswer), timeout)
            timeout -= time.time() - start_time

            # Unpack into tables.
            if isinstance(msg, OpGcExport):
                for export_position, wire_delta in zip(msg.export_positions, msg.wire_deltas):
                    self.gc_exports[export_position] = self.gc_exports.get(export_position, 0) + wire_delta
                return None, timeout

            if isinstance(msg, OpGcAnswer):
                for answer_position in msg.answer_positions:
                    self.gc_answers.add(answer_position)
                return None, timeout

            return msg, timeout


class OpGcExportTest(GCTestCase):
    """ `op:gc-export` - Garbage Collection for normal object exports """

    def test_gc_export_emitted_single_object(self):
        """ op:gc-export is emitted for an object """
        self.remote = self.netlayer.connect(self.ocapn_uri)
        self.remote.setup_session(self.captp_version)

        echo_gc_refr = self.remote.fetch_object(b"IO58l1laTyhcrgDKbEzFOO32MDd6zE5w")
        a_local_obj = self.remote.next_import_object

        # The idea here is we're specificing `a_local_obj` in the message, but once the other side
        # has delivered the message, the echo actor shouldn't have any need for this and will cause
        # a GC to occur.
        deliver_op = OpDeliver(echo_gc_refr, [a_local_obj], False, False)
        self.remote.send_message(deliver_op)

        timeout = 15
        while timeout > 0:
            try:
                other_msg, timeout = self._handle_gc_message(timeout=timeout)
            except TimeoutError:
                break
            # Got expected GC message.
            if self.gc_exports.get(a_local_obj.position) == 1:
                return
        raise Exception("Did not see expected op:gc-export within reasonable time.")

    def test_gc_export_with_multiple_refrences(self):
        """ op:gc-export has correct wire-delta for multiple references in the same message """
        self.remote = self.netlayer.connect(self.ocapn_uri)
        self.remote.setup_session(self.captp_version)

        echo_gc_refr = self.remote.fetch_object(b"IO58l1laTyhcrgDKbEzFOO32MDd6zE5w")
        a_local_obj = self.remote.next_import_object
        ref_count = 4

        deliver_op = OpDeliver(echo_gc_refr, [a_local_obj]*ref_count, False, False)
        self.remote.send_message(deliver_op)

        # The GC operation messages could be sent as one or multiple messages, so long as
        # the wire delta of all messages add up to the wire delta we're expecting it's
        # valid behavor.
        timeout = 15
        while timeout > 0:
            try:
                other_messsages, timeout = self._handle_gc_message(timeout=timeout)
            except TimeoutError:
                break

            if self.gc_exports.get(a_local_obj.position) == ref_count:
                return

        raise Exception("Did not see expected op:gc-export within reasonable time.")

    def test_gc_export_with_multiple_refrences_in_different_messages(self):
        """ op:gc-export has correct wire-delta for multiple references in different messages """
        self.remote = self.netlayer.connect(self.ocapn_uri)
        self.remote.setup_session(self.captp_version)

        echo_gc_refr = self.remote.fetch_object(b"IO58l1laTyhcrgDKbEzFOO32MDd6zE5w")
        a_local_obj = self.remote.next_import_object
        ref_count = 4

        for i in range(ref_count):
            deliver_op = OpDeliver(echo_gc_refr, [a_local_obj], False, False)
            self.remote.send_message(deliver_op)

        # The GC operation messages could be sent as one or multiple messages, so long as
        # the wire delta of all messages add up to the wire delta we're expecting it's
        # valid behavor.
        timeout = 15
        while timeout > 0:
            try:
                other_messsages, timeout = self._handle_gc_message(timeout=timeout)
            except TimeoutError:
                break

            if self.gc_exports.get(a_local_obj.position) == ref_count:
                return

        raise Exception("Did not see expected op:gc-export within reasonable time.")


class OpGcAnswerTest(GCTestCase):
    """ `op:gc-answer` - Garbage Collection for promises (answers) """

    def test_gc_answer(self):
        self.remote = self.netlayer.connect(self.ocapn_uri)
        self.remote.setup_session(self.captp_version)
        greeter_ref = self.remote.fetch_object(b"VMDDd1voKWarCe2GvgLbxbVFysNzRPzx")

        object_to_greet = self.remote.next_import_object
        op_deliver = OpDeliver(greeter_ref, [object_to_greet], False, False)
        self.remote.send_message(op_deliver)

        # Once we've got the greeting, we'll fulfill the promise then
        # wait for the GC operation which should come soon after.
        greeting_op = self.remote.expect_message_to(object_to_greet.to_desc_export())

        greeting_reply = OpDeliver(
            greeting_op.exported_resolve_me_desc,
            [Symbol("fulfill"), "Hello"],
            False, False
        )
        self.remote.send_message(greeting_reply)

        timeout = 15
        while timeout > 0:
            try:
                other_messages, timeout = self._handle_gc_message(timeout=timeout)
            except TimeoutError:
                break
            if greeting_op.answer_position in self.gc_answers:
                return
        raise Exception("Did not see expected op:gc-answer within reasonable time.")
