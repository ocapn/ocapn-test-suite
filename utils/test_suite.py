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

import time
import unittest

from utils.cryptography import Crypto
from utils.captp_types import *
from contrib.syrup import Record, Symbol, syrup_encode


class CapTPTestLoader(unittest.loader.TestLoader):
    """ Custom loader which provides the netlayer when constructing the test cases """
    def __init__(self, netlayer, ocapn_uri, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.netlayer = netlayer
        self.ocapn_uri = ocapn_uri

    def loadTestsFromTestCase(self, test_case_class):
        if issubclass(test_case_class, CapTPTestCase):
            names = self.getTestCaseNames(test_case_class)
            tests = [test_case_class(self.netlayer, self.ocapn_uri, method_name) for method_name in names]
            return self.suiteClass(tests)
        
        return super().loadTestsFromTestCase(test_case_class)

class CapTPTestRunner(unittest.TextTestRunner):
    
    def __init__(self, netlayer, ocapn_uri, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.netlayer = netlayer
        self.ocapn_uri = ocapn_uri

    def loadTests(self, test_module=None):
        loader = CapTPTestLoader(self.netlayer, self.ocapn_uri)
        if test_module:
            return loader.loadTestsFromName(test_module)
        return loader.discover("tests", pattern="*.py")

class CapTPTestCase(unittest.TestCase, Crypto):
    """ Base class for all CapTP tests """

    def __init__(self, netlayer, ocapn_uri, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.netlayer = netlayer
        self.ocapn_uri = ocapn_uri
        self.remote = None

    def setUp(self) -> None:
        self.remote = self.netlayer.connect(self.ocapn_uri)
        return super().setUp()

    def tearDown(self) -> None:
        if self.remote is not None:
            self.remote.close()
        return super().tearDown()


class CompleteCapTPTestCase(CapTPTestCase):
    """ Sets up a CapTP session for each test case """

    def __init__(self, netlayer, ocapn_uri, *args, **kwargs):
        super().__init__(netlayer, ocapn_uri, *args, **kwargs)
        self._next_answer_pos = 0
        self._next_object_pos = 0
        self._bootstrap_object = None

    def setUp(self) -> None:
        super().setUp()

        # Get their `op:start-session` message
        remote_start_session = self.remote.receive_message()
        assert isinstance(remote_start_session, OpStartSession)

        pubkey, privkey = self._generate_key()
        location = self.netlayer.location

        # Create the signature.
        my_location = Record(
            label=Symbol("my-location"),
            args=[location.to_syrup_record()]
        )
        location_sig = privkey.sign(syrup_encode(my_location))
        start_session_op = OpStartSession(
            remote_start_session.captp_version,
            pubkey,
            location,
            location_sig
        )
        self.remote.send_message(start_session_op)

    @property
    def _next_import_object(self) -> DescImportObject:
        """ Returns the next object position """
        position = self._next_answer_pos
        self._next_answer_pos += 1
        return DescImportObject(position)

    @property
    def _next_answer(self) -> DescAnswer:
        """ Returns the next answer position """
        position = self._next_answer_pos
        self._next_answer_pos += 1
        return DescAnswer(position)
    
    def get_bootstrap_object(self, pipeline=False) -> DescAnswer | DescExport:
        """" Gets the bootstrap object from the remote session """
        if self._bootstrap_object is not None:
            return self._bootstrap_object

        bootstrap_op = OpBootstrap(self._next_answer.position, self._next_import_object)
        self.remote.send_message(bootstrap_op)
        if pipeline:
            return DescAnswer(bootstrap_op.answer_position)
        
        export_desc = bootstrap_op.resolve_me_desc.to_desc_export()
        message = self._expect_message_to(export_desc)
        assert message.args[0] == Symbol("fulfill")
        assert isinstance(message.args[1], DescImportObject)
        self._bootstrap_object = message.args[1].to_desc_export()
        return self._bootstrap_object

    def _fetch_object(self, swiss_num, pipeline=False) -> DescExport:
        """ Fetches an object from the remote bootstrap object """
        bootstrap_object = self.get_bootstrap_object(pipeline=pipeline)
        fetch_msg = OpDeliver(
            to=bootstrap_object,
            args=[Symbol("fetch"), swiss_num],
            answer_position=self._next_answer_pos if pipeline else False,
            resolve_me_desc=self._next_import_object
        )
        self.remote.send_message(fetch_msg)
        if pipeline:
            self._next_answer_pos += 1
            return fetch_msg.vow
        
        response = self._expect_promise_resolution(fetch_msg.exported_resolve_me_desc)
        assert response.args[0] == Symbol("fulfill")
        fetched_object = response.args[1]
        assert isinstance(fetched_object, DescImportObject)
        return fetched_object.to_desc_export()

    def _expect_message_to(self, recipient: DescExport, timeout=60) -> OpDeliver | OpDeliverOnly | None:
        """ Reads messages until one is sent to the given recipient """

        while timeout >= 0:
            start_time = time.time()
            message = self.remote.receive_message(timeout=timeout)
            end_time = time.time()
            timeout -= end_time - start_time

            # Skip messages which aren't deliver or deliver-only
            if not isinstance(message, (OpDeliver, OpDeliverOnly)):
                continue
            
            # If the message is to the recipient, return it
            if message.to == recipient:
                return message
    
    def _expect_promise_resolution(self, resolve_me_desc, timeout=60) -> OpDeliver | OpDeliverOnly | None:
        """ Reads until a promise resolves to a value """        
        while timeout >= 0:
            start_time = time.time()
            message = self._expect_message_to(resolve_me_desc, timeout=timeout)
            end_time = time.time()
            timeout -= end_time - start_time

            # Check it's a fulfill
            assert message.args[0] in [Symbol("fulfill"), Symbol("break")]

            # If the promise has broken, return that.
            if message.args[0] == Symbol("break"):
                return message

            # If the resolution is another promise, keep going
            if isinstance(message.args[1], DescImportPromise):
                # Now we have to construct a listen message to get the answer
                # from the promise provided to us.
                listen_op = OpListen(
                    message.args[1].as_export,
                    self._next_import_object,
                    wants_partial=False
                )
                self.remote.send_message(listen_op)
                resolve_me_desc = listen_op.exported_resolve_me_desc
                continue

            return message
                

