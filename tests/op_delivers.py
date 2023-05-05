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
from utils.test_suite import CompleteCapTPTestCase

class OpDeliverOnly(CompleteCapTPTestCase):
    """ `op:deliver-only` - Send a mesage to an actor without a reply """

    def test_send_deliver_only(self):
        """ Send a message to an actor without a reply """
        greeter_refr = self._fetch_object(b"VMDDd1voKWarCe2GvgLbxbVFysNzRPzx")
        # Send a message to the greeter, telling them to greet us.
        object_to_greet = self._next_import_object
        message = Record(
            Symbol("op:deliver-only"),
            [greeter_refr, [object_to_greet]]
        )
        self.netlayer.send_message(message)

        object_to_greet_export = self._import_object_to_export(object_to_greet)
        response = self._expect_message_to(object_to_greet_export)

        to, args = response.args
        self.assertEqual(args, ["Hello"])
    
    def test_deliver_with_resolver(self):
        """ Deliver occurs with a response to the resolve me descriptor """
        echo_refr = self._fetch_object(b"IO58l1laTyhcrgDKbEzFOO32MDd6zE5w")

        resolve_me_desc = self._next_import_object
        sent_args = ["foo", 1, False, b"bar", ["baz"]]
        message = Record(
            Symbol("op:deliver"),
            [
                echo_refr,
                sent_args,
                False,
                resolve_me_desc
            ],
        )
        self.netlayer.send_message(message)

        exported_resolve_me_desc = self._import_object_to_export(resolve_me_desc)
        response = self._expect_promise_resolution(exported_resolve_me_desc)

        to, args = response.args
        self.assertEqual(args[0], Symbol("fulfill"))
        self.assertEqual(args[1], sent_args)
    
    def test_deliver_promise_pipeline(self):
        """ Can promise pipeline on multiple messages """
        car_factory_builder_refr = self._fetch_object(
            b"JadQ0++RzsD4M+40uLxTWVaVqM10DcBJ",
            pipeline=True
        )

        # First we'll send a message to the car factory builder, asking it to
        # build us a car factory.
        car_factory_resolve_me_desc = self._next_import_object
        car_factory_vow = self._next_answer
        self.netlayer.send_message(
            Record(
                Symbol("op:deliver"),
                [
                    car_factory_builder_refr,
                    [],
                    car_factory_vow.args[0],
                    car_factory_resolve_me_desc
                ]
            )
        )
        
        # Now send a message to the promise of a car factory asking it to build
        # us a car.
        car_vow = self._next_answer
        car_resolve_me_desc = self._next_import_object
        self.netlayer.send_message(
            Record(
                Symbol("op:deliver"),
                [
                    car_factory_vow,
                    [[Symbol("red"), Symbol("zoomracer")]],
                    car_vow.args[0],
                    car_resolve_me_desc
                ]
            )
        )

        # Finally send a message to the promise of a car, telling it to drive
        drive_resolve_me_desc = self._next_import_object
        self.netlayer.send_message(
            Record(
                Symbol("op:deliver"),
                [car_vow, [], False, drive_resolve_me_desc],
            )
        )
        export_drive_resolve_me_desc = self._import_object_to_export(drive_resolve_me_desc)
        response = self._expect_promise_resolution(export_drive_resolve_me_desc)
        to, args = response.args
        self.assertEqual(args[0], Symbol("fulfill"))
        self.assertEqual(args[1], "Vroom! I am a red zoomracer car!")
    
    def test_promise_pipeline_with_break(self):
        """ Pomise pipelining handles a broken promise when pipelining """
        car_factory_builder_refr = self._fetch_object(
            b"JadQ0++RzsD4M+40uLxTWVaVqM10DcBJ",
            pipeline=True
        )

        # First we'll send a message to the car factory builder, asking it to
        # build us a car factory.
        car_factory_resolve_me_desc = self._next_import_object
        car_factory_vow = self._next_answer
        self.netlayer.send_message(
            Record(
                Symbol("op:deliver"),
                [
                    car_factory_builder_refr,
                    [],
                    car_factory_vow.args[0],
                    car_factory_resolve_me_desc
                ]
            )
        )

        # Lets introduce the error by providing invalid arguments to the car.
        car_vow = self._next_answer
        car_resolve_me_desc = self._next_import_object
        self.netlayer.send_message(
            Record(
                Symbol("op:deliver"),
                [
                    car_factory_vow,
                    [[1,2,3,4,5]],
                    car_vow.args[0],
                    car_resolve_me_desc
                ]
            )
        )

        # Finally send a message to the promise of a car, telling it to drive
        drive_resolve_me_desc = self._next_import_object
        self.netlayer.send_message(
            Record(
                Symbol("op:deliver"),
                [car_vow, [], False, drive_resolve_me_desc],
            )
        )
        export_drive_resolve_me_desc = self._import_object_to_export(drive_resolve_me_desc)
        response = self._expect_promise_resolution(export_drive_resolve_me_desc)
        to, args = response.args
        self.assertEqual(args[0], Symbol("break"))
        self.assertTrue(len(args) == 2)