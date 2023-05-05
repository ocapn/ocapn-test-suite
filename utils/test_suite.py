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
from contrib.syrup import Record, Symbol, syrup_encode


class CapTPTestLoader(unittest.loader.TestLoader):
    """ Custom loader which provides the netlayer when constructing the test cases """
    def __init__(self, netlayer, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.netlayer = netlayer

    def loadTestsFromTestCase(self, test_case_class):
        if issubclass(test_case_class, CapTPTestCase):
            names = self.getTestCaseNames(test_case_class)
            tests = [test_case_class(self.netlayer, method_name) for method_name in names]
            return self.suiteClass(tests)
        
        return super().loadTestsFromTestCase(test_case_class)

class CapTPTestRunner(unittest.TextTestRunner):
    
    def __init__(self, netlayer, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.netlayer = netlayer

    def loadTests(self, test_module=None):
        loader = CapTPTestLoader(self.netlayer)
        if test_module:
            return loader.loadTestsFromName(test_module)
        return loader.discover("tests", pattern="*.py")

class CapTPTestSuite(unittest.TestSuite):
    """ Custom test suite for CapTP which takes a netlayer to communicate over """

    def __init__(self, netlayer, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for test in self:
            if isinstance(test, CapTPTestCase):
                test.netlayer = netlayer

class CapTPTestCase(unittest.TestCase, Crypto):
    """ Base class for all CapTP tests """

    def __init__(self, netlayer, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.netlayer = netlayer

    def setUp(self) -> None:
        self.netlayer.connect()
        return super().setUp()

    def tearDown(self) -> None:
        self.netlayer.close()
        return super().tearDown()


class CompleteCapTPTestCase(CapTPTestCase):
    """ Sets up a CapTP session for each test case """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._bootstrap_object = None
        self._next_answer_pos = 1 # we use zero for the bootstrap object.
        self._next_object_pos = 0

    def setUp(self) -> None:
        super().setUp()

        # Get their `op:start-session` message
        remote_start_session = self.netlayer.receive_message()

        # Send our `op:start-session`
        pubkey, privkey = self._generate_key()
        location = self.netlayer.location
        my_location = Record(
            label=Symbol("my-location"),
            args=[location]
        )
        location_sig = privkey.sign(syrup_encode(my_location))
        start_session_op = Record(
            label=Symbol("op:start-session"),
            args=[
                remote_start_session.args[0],
                self._key_pair_to_captp(pubkey),
                location,
                self._signature_to_captp(location_sig)
            ]
        )
        self.netlayer.send_message(start_session_op)
    
    def _import_object_to_export(self, import_object: Record) -> Record:
        """ Converts an import-object (or import-promise) to desc:export """
        valid_import_objects = (
            Symbol("desc:import-object"),
            Symbol("desc:import-promise")
        )
        assert import_object.label in valid_import_objects
        return Record(
            Symbol("desc:export"),
            import_object.args
        )

    @property
    def _next_import_object(self):
        """ Returns the next object position """
        import_object = Record(
            Symbol("desc:import-object"),
            [self._next_object_pos]
        )
        self._next_object_pos += 1
        return import_object

    @property
    def _next_answer(self):
        """ Returns the next answer position """
        answer = Record(
            Symbol("desc:answer"),
            [self._next_answer_pos]
        )
        self._next_answer_pos += 1
        return answer
    
    @property
    def bootstrap_object(self):
        if self._bootstrap_object is not None:
            return self._bootstrap_object

        self._bootstrap_object = self._next_import_object
        bootstrap_op = Record(
            Symbol("op:bootstrap"),
            [0, self._bootstrap_object]
        )
        self.netlayer.send_message(bootstrap_op)
        return self._bootstrap_object

    def _fetch_object(self, swiss_num, pipeline=False):
        """ Fetches an object from the remote bootstrap object """
        resolve_me_desc = Record(
            Symbol("desc:resolve-me"),
            [0]
        )
        fetch_msg = Record(
            Symbol("op:deliver"),
            [
                self.bootstrap_object,
                [Symbol("fetch")],
                self._next_answer_pos if pipeline else False,
                resolve_me_desc
            ]
        )
        self.netlayer.send_message(fetch_msg)

        if pipeline:
            object_location = Record(
                Symbol("desc:answer"),
                [self._next_answer_pos]
            )
            self._next_answer_pos += 1
            return object_location
        else:
            return self.expect_message_to(resolve_me_desc)

    def _expect_message_to(self, recipient, timeout=60):
        """ Reads messages until one is sent to the given recipient """
        deliver = Symbol("op:deliver")
        deliver_only = Symbol("op:deliver-only")

        while timeout >= 0:
            start_time = time.time()
            message = self.netlayer.receive_message(timeout=timeout)
            end_time = time.time()
            timeout -= end_time - start_time

            # Skip messages which aren't deliver or deliver-only
            if message.label!= deliver and message.label != deliver_only:
                continue

            # If the message is to the recipient, return it
            if message.args[0] == recipient:
                return message
                

