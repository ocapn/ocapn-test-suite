# Copyright 2025 Jessica Tallon
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
from utils.captp_types import OpDeliver, OpDeliverOnly, OpGet, OpIndex, OpListen

class ResolverTestCase(CapTPTestCase):

    def setUp(self, *args, **kwargs):
        rtn = super().setUp(*args, **kwargs)
        # Connect and and fetch the echo object
        self.remote = self.netlayer.connect(self.ocapn_uri)
        self.remote.setup_session(self.captp_version)
        self.echo_refr = self.remote.fetch_object(
            b"IO58l1laTyhcrgDKbEzFOO32MDd6zE5w"
        )
        self.promise_and_resolver_refr = self.remote.fetch_object(
            b"IokCxYmMj04nos2JN1TDoY1bT8dXh6Lr"
        )
        return rtn

    def make_op_index_and_listen(self, to, index):
        # Send the OpIndex
        index_op = OpIndex(
            to=to,
            index=index,
            new_answer_pos=self.remote.next_answer.position
        )
        self.remote.send_message(index_op)

        # Send listen to new Answer position to get the result!
        listen_op = OpListen(
            to=index_op.answer,
            resolve_me_desc=self.remote.next_import_object,
            wants_partial=False
        )
        self.remote.send_message(listen_op)

        return listen_op.exported_resolve_me_desc

    def make_promise_pair(self):
        """ Returns a promise and resolver pair """
        deliver_op = OpDeliver(
            to=self.promise_and_resolver_refr,
            args=[],
            answer_position=False,
            resolve_me_desc=self.remote.next_import_object
        )
        self.remote.send_message(deliver_op)
        response = self.remote.expect_promise_resolution(deliver_op.exported_resolve_me_desc)
        assert response.args[0] == Symbol("fulfill")
        assert isinstance(response.args[1], list)
        vow, resolver = response.args[1]
        return vow, resolver

class TestOpIndex(ResolverTestCase):
    """ `op:index` - used to get an item from a list at a specific index """

    def test_op_index_success_desc_answer(self):
        """ op:index on desc:answer target """
        # Deliver a CapTP list to the echo so the desc:answer will point at
        # the list we're sending to them.
        deliver_op = OpDeliver(
            to=self.echo_refr,
            args=[Symbol("foo"), Symbol("bar"), Symbol("baz")],
            answer_position=self.remote.next_answer.position,
            resolve_me_desc=self.remote.next_import_object
        )
        self.remote.send_message(deliver_op)

        # Send the op:index and then a op:listen to the new answer position
        promise = self.make_op_index_and_listen(to=deliver_op.vow, index=1)

        # Expect a promise resolution with the Symbol("bar")
        response = self.remote.expect_promise_resolution(promise)
        self.assertEqual(response.args[0], Symbol("fulfill"))
        self.assertEqual(response.args[1], Symbol("bar"))

    def test_op_index_success_desc_export(self):
        """ op:index on desc:export target """
        # Fetch the promise and resolver actor to make a desc:export.
        vow, resolver = self.make_promise_pair()

        # Do an op:index on the new promise we just created.
        index_op = OpIndex(
            to=vow.to_desc_export(),
            index=2,
            new_answer_pos=self.remote.next_answer.position
        )
        self.remote.send_message(index_op)
        # Listen to the answer
        listen_op = OpListen(
            to=index_op.answer,
            resolve_me_desc=self.remote.next_import_object,
            wants_partial=False
        )
        self.remote.send_message(listen_op)

        # Lets resolve our promise with a list of values
        resolve_with = [100, 200, 300, 400]
        resolve_msg = OpDeliverOnly(
            to=resolver.to_desc_export(),
            args=[Symbol("fulfill"), resolve_with]
        )
        self.remote.send_message(resolve_msg)

        # Finally lets expect our response from our listen and check we got the
        # value we expected.
        response = self.remote.expect_promise_resolution(listen_op.exported_resolve_me_desc)
        self.assertEqual(response.args[0], Symbol("fulfill"))
        self.assertEqual(response.args[1], resolve_with[index_op.index])

    def test_op_index_on_broken_promise(self):
        """ Test op:index on a broken promise target results in broken promise """
        # Fetch the promise and resolver actor to make a desc:export.
        vow, resolver = self.make_promise_pair()

        # Do an op:index on the new promise we just created.
        index_op = OpIndex(
            to=vow.to_desc_export(),
            index=2,
            new_answer_pos=self.remote.next_answer.position
        )
        self.remote.send_message(index_op)

        # Listen to the answer
        listen_op = OpListen(
            to=index_op.answer,
            resolve_me_desc=self.remote.next_import_object,
            wants_partial=False
        )
        self.remote.send_message(listen_op)

        # Now lets break the promise
        err_symbol = Symbol("oh-no")
        break_msg = OpDeliverOnly(
            to=resolver.to_desc_export(),
            args=[Symbol("break"), err_symbol]
        )
        self.remote.send_message(break_msg)

        # Finally check what we got back.
        response = self.remote.expect_promise_resolution(listen_op.exported_resolve_me_desc)
        assert response.args[0] == Symbol("break")

    def test_op_index_fails_on_non_list(self):
        """ op:index on a non-list target results in a broken promise """
        # Fetch the promise and resolver actor to make a desc:export.
        vow, resolver = self.make_promise_pair()

        # Do an op:index on the new promise we just created.
        index_op = OpIndex(
            to=vow.to_desc_export(),
            index=2,
            new_answer_pos=self.remote.next_answer.position
        )
        self.remote.send_message(index_op)

        # Listen to the answer
        listen_op = OpListen(
            to=index_op.answer,
            resolve_me_desc=self.remote.next_import_object,
            wants_partial=False
        )
        self.remote.send_message(listen_op)

        # Now lets resolve the promise with a non-list value
        resolve_msg = OpDeliverOnly(
            to=resolver.to_desc_export(),
            args=[Symbol("fulfill"), Symbol("not-a-list")]
        )
        self.remote.send_message(resolve_msg)

        # Finally check what we got back.
        response = self.remote.expect_promise_resolution(listen_op.exported_resolve_me_desc)
        assert response.args[0] == Symbol("break")


class TestOpGet(ResolverTestCase):
    """ `op:get` - used to get an item from an OCapN struct """

    def test_op_get_success_desc_answer(self):
        """ Successful op:get on desc:answer target """

        # Deliver a CapTP struct to the echo so the desc:answer will point at
        # the struct we're sending to them.
        deliver_op = OpDeliver(
            to=self.echo_refr,
            args=[{"foo": 72, "bar": "baz"}],
            answer_position=self.remote.next_answer.position,
            resolve_me_desc=self.remote.next_import_object
        )
        self.remote.send_message(deliver_op)

        # Since echo will return a list of values we sent, use op:index to get the first value
        index_op = OpIndex(
            to=deliver_op.vow,
            index=0,
            new_answer_pos=self.remote.next_answer.position
        )
        self.remote.send_message(index_op)

        # Send the OpGet
        get_op = OpGet(
            to=index_op.answer,
            field_name="foo",
            new_answer_pos=self.remote.next_answer.position
        )
        self.remote.send_message(get_op)

        # Send listen to new Answer position to get the result!
        listen_op = OpListen(
            to=get_op.answer,
            resolve_me_desc=self.remote.next_import_object,
            wants_partial=False
        )
        self.remote.send_message(listen_op)

        # Expect a promise resolution with the value of 72
        response = self.remote.expect_promise_resolution(listen_op.exported_resolve_me_desc)
        self.assertEqual(response.args[0], Symbol("fulfill"))

    def test_op_get_success_desc_export(self):
        """ Test op:get on desc:export target"""
        # Make promise pair
        vow, resolver = self.make_promise_pair()

        fulfill_msg = OpDeliverOnly(
            to=resolver.to_desc_export(),
            args=[Symbol("fulfill"), {"foo": 72, "bar": "baz"}]
        )
        self.remote.send_message(fulfill_msg)

        # Send the OpGet
        get_op = OpGet(
            to=vow.to_desc_export(),
            field_name="foo",
            new_answer_pos=self.remote.next_answer.position
        )
        self.remote.send_message(get_op)

        # Send listen to new Answer position to get the result!
        listen_op = OpListen(
            to=get_op.answer,
            resolve_me_desc=self.remote.next_import_object,
            wants_partial=False
        )
        self.remote.send_message(listen_op)

        # Expect a promise resolution with the value of 72
        response = self.remote.expect_promise_resolution(listen_op.exported_resolve_me_desc)
        self.assertEqual(response.args[0], Symbol("fulfill"))
        self.assertEqual(response.args[1], 72)

    def test_op_get_broken_promise(self):
        """ Test op:get on a broken promise target results in a broken promise """
        # Make promise pair
        vow, resolver = self.make_promise_pair()

        break_msg = OpDeliverOnly(
            to=resolver.to_desc_export(),
            args=[Symbol("break"), Symbol("oh-no")],
        )
        self.remote.send_message(break_msg)

        # Send the OpGet
        get_op = OpGet(
            to=vow.to_desc_export(),
            field_name="foo",
            new_answer_pos=self.remote.next_answer.position
        )
        self.remote.send_message(get_op)

        # Send listen to new Answer position to get the result!
        listen_op = OpListen(
            to=get_op.answer,
            resolve_me_desc=self.remote.next_import_object,
            wants_partial=False
        )
        self.remote.send_message(listen_op)

        # Expect get_op promise to break.
        response = self.remote.expect_promise_resolution(listen_op.exported_resolve_me_desc)
        self.assertEqual(response.args[0], Symbol("break"))

    def test_op_get_not_struct(self):
        """ Test op:get on a non-struct target results in a broken promise """
        # Make promise pair
        vow, resolver = self.make_promise_pair()

        fulfill_msg = OpDeliverOnly(
            to=resolver.to_desc_export(),
            args=[Symbol("fulfill"), Symbol("not-a-struct")],
        )
        self.remote.send_message(fulfill_msg)

        # Send the OpGet
        get_op = OpGet(
            to=vow.to_desc_export(),
            field_name="foo",
            new_answer_pos=self.remote.next_answer.position
        )
        self.remote.send_message(get_op)

        # Send listen to new Answer position to get the result!
        listen_op = OpListen(
            to=get_op.answer,
            resolve_me_desc=self.remote.next_import_object,
            wants_partial=False
        )
        self.remote.send_message(listen_op)

        # Expect get_op promise to break.
        response = self.remote.expect_promise_resolution(listen_op.exported_resolve_me_desc)
        self.assertEqual(response.args[0], Symbol("break"))

# TODO: Test OpUntag.