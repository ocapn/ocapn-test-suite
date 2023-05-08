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

class OpListen(CompleteCapTPTestCase):
    """ `op:listen` - Request notification on a promise """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._promise_resolver = None

    @property
    def promise_resolver_refr(self):
        """ The promise resolver object which provides a promise and resolver """
        return self._fetch_object(b"IokCxYmMj04nos2JN1TDoY1bT8dXh6Lr")
    
    def make_promise_resolver_pair(self):
        """ Returns a promise and resolver pair """
        resolve_me_desc = self._next_import_object
        get_promise_pair_msg = Record(
            Symbol("op:deliver"),
            [
                self.promise_resolver_refr,
                [],
                False,
                resolve_me_desc
            ]
        )
        self.netlayer.send_message(get_promise_pair_msg)
        exported_resolve_me_desc = self._import_object_to_export(resolve_me_desc)
        response = self._expect_promise_resolution(exported_resolve_me_desc)
        return response.args[1][1]

    def make_listen_msg(self, on: Record, wants_partial=False):
        resolve_me_desc = self._next_import_object
        listen_op = Record(
            Symbol("op:listen"),
            [on, resolve_me_desc, False]
        )
        return listen_op, resolve_me_desc


    def test_op_listen_to_promise_and_fulfill(self):
        """ Get a notification when a promise is fulfilled """
        # First lets get a promise and resolver
        vow, resolver = self.make_promise_resolver_pair()
        vow_refr = self._import_object_to_export(vow)
        resolver_refr = self._import_object_to_export(resolver)

        # Now lets listen on the promise
        listen_op, resolve_me_desc = self.make_listen_msg(vow_refr)
        self.netlayer.send_message(listen_op)

        # Resolve the promise
        resolved_promise_with = Symbol("ok")
        resolve_msg = Record(
            Symbol("op:deliver-only"),
            [resolver_refr, [Symbol("fulfill"), resolved_promise_with]]
        )
        self.netlayer.send_message(resolve_msg)

        # Check we get a resolution to our object.
        exported_resolve_me_desc = self._import_object_to_export(resolve_me_desc)
        response = self._expect_promise_resolution(exported_resolve_me_desc)
        self.assertEqual(response.args[1][0], Symbol("fulfill"))
        self.assertEqual(response.args[1][1], resolved_promise_with)
    
    def test_op_listen_to_promise_and_break(self):
        """ Get a notification when a promise is broken """
        # First lets get a promise and resolver
        vow, resolver = self.make_promise_resolver_pair()
        vow_refr = self._import_object_to_export(vow)
        resolver_refr = self._import_object_to_export(resolver)

        # Now lets listen on the promise
        listen_op, resolve_me_desc = self.make_listen_msg(vow_refr)
        self.netlayer.send_message(listen_op)

        # Break the promise
        err_symbol = Symbol("oh-no")
        break_msg = Record(
            Symbol("op:deliver-only"),
            [resolver_refr, [Symbol("break"), err_symbol]]
        )
        self.netlayer.send_message(break_msg)

        # Check we get a resolution to our object.
        exported_resolve_me_desc = self._import_object_to_export(resolve_me_desc)
        response = self._expect_promise_resolution(exported_resolve_me_desc)
        self.assertEqual(response.args[1][0], Symbol("break"))
        self.assertEqual(response.args[1][1], err_symbol)

    def test_op_listen_already_has_answer(self):
        """ We get a notification when listening on a resolved promise """
        # First lets get a promise and resolver
        vow, resolver = self.make_promise_resolver_pair()
        vow_refr = self._import_object_to_export(vow)
        resolver_refr = self._import_object_to_export(resolver)

        # Lets resolve the promise
        resolved_promise_with = Symbol("ok")
        resolve_msg = Record(
            Symbol("op:deliver-only"),
            [resolver_refr, [Symbol("fulfill"), resolved_promise_with]]
        )
        self.netlayer.send_message(resolve_msg)

        # Now lets listen on the promise
        listen_op, resolve_me_desc = self.make_listen_msg(vow_refr)
        self.netlayer.send_message(listen_op)

        # Check we get a resolution to our object.
        exported_resolve_me_desc = self._import_object_to_export(resolve_me_desc)
        response = self._expect_promise_resolution(exported_resolve_me_desc)
        self.assertEqual(response.args[1][0], Symbol("fulfill"))
        self.assertEqual(response.args[1][1], resolved_promise_with)