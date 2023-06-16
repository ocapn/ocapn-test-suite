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

from typing import Tuple

from contrib.syrup import Symbol
from utils.test_suite import CapTPTestCase, retry_on_network_timeout
from utils.captp_types import OpDeliver, OpDeliverOnly, DescImportObject, OpListen


class OpListenTest(CapTPTestCase):
    """ `op:listen` - Request notification on a promise """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._promise_resolver_refr = None

    @property
    def promise_resolver_refr(self):
        """ The promise resolver object which provides a promise and resolver """
        if self._promise_resolver_refr is None:
            self._promise_resolver_refr = self.remote.fetch_object(b"IokCxYmMj04nos2JN1TDoY1bT8dXh6Lr")
        return self._promise_resolver_refr

    def make_promise_resolver_pair(self) -> Tuple[DescImportObject, DescImportObject]:
        """ Returns a promise and resolver pair """
        deliver_op = OpDeliver(
            to=self.promise_resolver_refr,
            args=[],
            answer_position=False,
            resolve_me_desc=self.remote.next_import_object
        )
        self.remote.send_message(deliver_op)
        response = self.remote.expect_promise_resolution(deliver_op.exported_resolve_me_desc)
        vow, resolver = response.args[1]
        return vow, resolver

    @retry_on_network_timeout
    def test_op_listen_to_promise_and_fulfill(self):
        """ Notified when a promise is fulfilled """
        self.remote.setup_session()

        # First lets get a promise and resolver
        vow, resolver = self.make_promise_resolver_pair()

        # Now lets listen on the promise
        listen_op = OpListen(
            to=vow.to_desc_export(),
            resolve_me_desc=self.remote.next_import_object,
            wants_partial=False,
        )
        self.remote.send_message(listen_op)

        # Resolve the promise
        resolved_promise_with = Symbol("ok")
        resolve_msg = OpDeliverOnly(
            to=resolver.to_desc_export(),
            args=[Symbol("fulfill"), resolved_promise_with]
        )
        self.remote.send_message(resolve_msg)

        # Check we get a resolution to our object.
        response = self.remote.expect_promise_resolution(listen_op.exported_resolve_me_desc)
        self.assertEqual(response.args, [Symbol("fulfill"), resolved_promise_with])

    @retry_on_network_timeout
    def test_op_listen_to_promise_and_break(self):
        """ Notified when a promise is broken """
        self.remote.setup_session()

        # First lets get a promise and resolver
        vow, resolver = self.make_promise_resolver_pair()

        # Now lets listen on the promise
        listen_op = OpListen(
            to=vow.to_desc_export(),
            resolve_me_desc=self.remote.next_import_object,
            wants_partial=False,
        )
        self.remote.send_message(listen_op)

        # Break the promise
        err_symbol = Symbol("oh-no")
        break_msg = OpDeliverOnly(
            to=resolver.to_desc_export(),
            args=[Symbol("break"), err_symbol]
        )
        self.remote.send_message(break_msg)

        # Check we get a resolution to our object.
        response = self.remote.expect_promise_resolution(listen_op.exported_resolve_me_desc)
        self.assertEqual(response.args, [Symbol("break"), err_symbol])

    @retry_on_network_timeout
    def test_op_listen_already_has_answer(self):
        """ Notified when listening on a resolved promise """
        self.remote.setup_session()

        # First lets get a promise and resolver
        vow, resolver = self.make_promise_resolver_pair()

        # Lets resolve the promise
        resolved_promise_with = Symbol("ok")
        resolve_msg = OpDeliverOnly(
            to=resolver.to_desc_export(),
            args=[Symbol("fulfill"), resolved_promise_with]
        )
        self.remote.send_message(resolve_msg)

        # Now lets listen on the promise
        listen_op = OpListen(
            to=vow.to_desc_export(),
            resolve_me_desc=self.remote.next_import_object,
            wants_partial=False,
        )
        self.remote.send_message(listen_op)

        # Check we get a resolution to our object.
        response = self.remote.expect_promise_resolution(listen_op.exported_resolve_me_desc)
        self.assertEqual(response.args, [Symbol("fulfill"), resolved_promise_with])
