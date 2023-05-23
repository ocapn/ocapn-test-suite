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

from contrib.syrup import Symbol
from utils.test_suite import CapTPTestCase
from utils.captp_types import OpDeliverOnly, OpDeliver


class OpDeliverOnlyTest(CapTPTestCase):
    """ `op:deliver-only` - Send a mesage to an actor without a reply """

    def test_send_deliver_only(self):
        """ Send a message to an actor without a reply """
        self.remote.setup_session()

        greeter_refr = self.remote.fetch_object(b"VMDDd1voKWarCe2GvgLbxbVFysNzRPzx")
        # Send a message to the greeter, telling them to greet us.
        object_to_greet = self.remote.next_import_object
        deliver_only_op = OpDeliverOnly(greeter_refr, [object_to_greet])
        self.remote.send_message(deliver_only_op)

        response = self.remote.expect_message_to(object_to_greet.to_desc_export())
        self.assertIsInstance(response, (OpDeliverOnly, OpDeliver))
        self.assertEqual(response.args, ["Hello"])


class OpDeliverTest(CapTPTestCase):
    """ `op:deliver` - Send a message to an actor with a reply """

    def test_deliver_with_resolver(self):
        """ Deliver occurs with a response to the resolve me descriptor """
        self.remote.setup_session()

        echo_refr = self.remote.fetch_object(b"IO58l1laTyhcrgDKbEzFOO32MDd6zE5w")

        deliver_op = OpDeliver(
            to=echo_refr,
            args=["foo", 1, False, b"bar", ["baz"]],
            answer_position=False,
            resolve_me_desc=self.remote.next_import_object
        )
        self.remote.send_message(deliver_op)

        response = self.remote.expect_promise_resolution(deliver_op.exported_resolve_me_desc)

        self.assertEqual(response.args[0], Symbol("fulfill"))
        self.assertEqual(response.args[1], deliver_op.args)

    def test_deliver_promise_pipeline(self):
        """ Can promise pipeline on multiple messages """
        self.remote.setup_session()

        car_factory_builder_refr = self.remote.fetch_object(
            b"JadQ0++RzsD4M+40uLxTWVaVqM10DcBJ",
            pipeline=True
        )

        # First we'll send a message to the car factory builder, asking it to
        # build us a car factory.
        build_car_factory_op = OpDeliver(
            to=car_factory_builder_refr,
            args=[],
            answer_position=self.remote.next_answer.position,
            resolve_me_desc=self.remote.next_import_object
        )
        self.remote.send_message(build_car_factory_op)

        # Now send a message to the promise of a car factory asking it to build
        # us a car.
        build_car_op = OpDeliver(
            to=build_car_factory_op.vow,
            args=[[Symbol("red"), Symbol("zoomracer")]],
            answer_position=self.remote.next_answer.position,
            resolve_me_desc=self.remote.next_import_object
        )
        self.remote.send_message(build_car_op)

        # Finally send a message to the promise of a car, telling it to drive
        drive_op = OpDeliver(
            to=build_car_op.vow,
            args=[],
            answer_position=False,
            resolve_me_desc=self.remote.next_import_object
        )
        self.remote.send_message(drive_op)
        response = self.remote.expect_promise_resolution(drive_op.exported_resolve_me_desc)
        self.assertEqual(response.args, [Symbol("fulfill"), "Vroom! I am a red zoomracer car!"])

    def test_promise_pipeline_with_break(self):
        """ Pomise pipelining handles a broken promise when pipelining """
        self.remote.setup_session()

        car_factory_builder_refr = self.remote.fetch_object(
            b"JadQ0++RzsD4M+40uLxTWVaVqM10DcBJ",
            pipeline=True
        )

        # First we'll send a message to the car factory builder, asking it to
        # build us a car factory.
        car_factory_build_op = OpDeliver(
            to=car_factory_builder_refr,
            args=[],
            answer_position=self.remote.next_answer.position,
            resolve_me_desc=self.remote.next_import_object
        )
        self.remote.send_message(car_factory_build_op)

        # Lets introduce the error by providing invalid arguments to the car.
        invalid_make_car_op = OpDeliver(
            to=car_factory_build_op.vow,
            args=[[1, 2, 3, 4, 5]],
            answer_position=self.remote.next_answer.position,
            resolve_me_desc=self.remote.next_import_object
        )
        self.remote.send_message(invalid_make_car_op)

        # Finally send a message to the promise of a car, telling it to drive
        drive_op = OpDeliver(
            to=invalid_make_car_op.vow,
            args=[],
            answer_position=False,
            resolve_me_desc=self.remote.next_import_object
        )
        self.remote.send_message(drive_op)
        response = self.remote.expect_promise_resolution(drive_op.exported_resolve_me_desc)

        self.assertIsInstance(response, (OpDeliver, OpDeliverOnly))
        self.assertEqual(response.args[0], Symbol("break"))
        self.assertTrue(len(response.args) == 2)
