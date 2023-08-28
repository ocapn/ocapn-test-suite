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
from utils.captp_types import OpGcExport, OpGcAnswer, OpDeliverOnly

class GCTestCase(CapTPTestCase):

    def _expect_gc_for_position(self, gc_type, position, timeout=30):
        while timeout > 0:
            start_time = time.time()
            gc_msg = self.remote.expect_message_type(gc_type, timeout)

            if isinstance(gc_msg, OpGcExport) and gc_msg.export_position == position:
                return gc_msg

            if isinstance(gc_msg, OpGcAnswer) and gc_msg.answer_position == position:
                return gc_msg

            timeout -= time.time() - start_time


class OpGcExportTest(GCTestCase):
    """ `op:gc-export` - Garbage Collection for normal object exports """

    @retry_on_network_timeout
    def test_gc_export_emitted_single_object(self):
        """ op:gc-export is emitted for an object """
        self.remote.setup_session(self.captp_version)

        echo_gc_refr = self.remote.fetch_object(b"IO58l1laTyhcrgDKbEzFOO32MDd6zE5w")
        a_local_obj = self.remote.next_import_object

        # The idea here is we're specificing `a_local_obj` in the message, but once the other side
        # has delivered the message, the echo actor shouldn't have any need for this and will cause
        # a GC to occur.
        deliver_only_op = OpDeliverOnly(
            echo_gc_refr,
            [a_local_obj]
        )
        self.remote.send_message(deliver_only_op)

        gc_msg = self._expect_gc_for_position(OpGcExport, a_local_obj.position)
        self.assertIsInstance(gc_msg, OpGcExport)
        self.assertEqual(gc_msg.export_position, a_local_obj.position)
        self.assertEqual(gc_msg.wire_delta, 1)

    @retry_on_network_timeout
    def test_gc_export_with_multiple_refrences(self):
        """ op:gc-export has correct wire-delta for multiple references in the same message """
        self.remote.setup_session(self.captp_version)

        echo_gc_refr = self.remote.fetch_object(b"IO58l1laTyhcrgDKbEzFOO32MDd6zE5w")
        a_local_obj = self.remote.next_import_object
        ref_count = 4

        deliver_only_op = OpDeliverOnly(
            echo_gc_refr,
            [a_local_obj]*ref_count
        )
        self.remote.send_message(deliver_only_op)

        # The GC operation messages could be sent as one or multiple messages, so long as
        # the wire delta of all messages add up to the wire delta we're expecting it's
        # valid behavor.
        timeout = 30
        seen_wire_delta = 0
        while timeout > 0 and seen_wire_delta < ref_count:
            start_time = time.time()
            gc_message = self._expect_gc_for_position(OpGcExport, a_local_obj.position, timeout)
            timeout -= time.time() - start_time
            if gc_message is None:
                continue

            seen_wire_delta += gc_message.wire_delta

        self.assertEqual(seen_wire_delta, ref_count)

    @retry_on_network_timeout
    def test_gc_export_with_multiple_refrences_in_different_messages(self):
        """ op:gc-export has correct wire-delta for multiple references in different messages """
        self.remote.setup_session(self.captp_version)

        echo_gc_refr = self.remote.fetch_object(b"IO58l1laTyhcrgDKbEzFOO32MDd6zE5w")
        a_local_obj = self.remote.next_import_object
        ref_count = 4

        for i in range(ref_count):
            deliver_only_op = OpDeliverOnly(
                echo_gc_refr,
                [a_local_obj]
            )
            self.remote.send_message(deliver_only_op)

        # The GC operation messages could be sent as one or multiple messages, so long as
        # the wire delta of all messages add up to the wire delta we're expecting it's
        # valid behavor.
        timeout = 30
        seen_wire_delta = 0
        while timeout > 0 and seen_wire_delta < ref_count:
            start_time = time.time()
            gc_message = self._expect_gc_for_position(OpGcExport, a_local_obj.position, timeout)
            timeout -= time.time() - start_time
            if gc_message is None:
                continue

            seen_wire_delta += gc_message.wire_delta

        self.assertEqual(seen_wire_delta, ref_count)


class OpGcAnswerTest(GCTestCase):
    """ `op:gc-answer` - Garbage Collection for promises (answers) """

    @retry_on_network_timeout
    def test_gc_answer(self):
        self.remote.setup_session(self.captp_version)
        greeter_ref = self.remote.fetch_object(b"VMDDd1voKWarCe2GvgLbxbVFysNzRPzx")

        object_to_greet = self.remote.next_import_object
        op_deliver_only = OpDeliverOnly(
            greeter_ref,
            [object_to_greet]
        )
        self.remote.send_message(op_deliver_only)

        # Once we've got the greeting, we'll fulfill the promise then
        # wait for the GC operation which should come soon after.
        greeting_op = self.remote.expect_message_to(object_to_greet.to_desc_export())

        greeting_reply = OpDeliverOnly(
            greeting_op.exported_resolve_me_desc,
            [Symbol("fulfill"), "Hello"]
        )
        self.remote.send_message(greeting_reply)

        gc_msg = self._expect_gc_for_position(OpGcAnswer, greeting_op.answer_position)
        
        self.assertIsInstance(gc_msg, OpGcAnswer)
        self.assertEqual(gc_msg.answer_position, greeting_op.answer_position)