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

import unittest


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


class CapTPTestCase(unittest.TestCase):
    """ Base class for all CapTP tests """

    def __init__(self, netlayer, ocapn_uri, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.netlayer = netlayer
        self.ocapn_uri = ocapn_uri
        self.remote = None
        self._next_answer_pos = 0
        self._next_import_object_pos = 0

    def setUp(self) -> None:
        self.remote = self.netlayer.connect(self.ocapn_uri)
        return super().setUp()

    def tearDown(self) -> None:
        if self.remote is not None:
            self.remote.close()
        return super().tearDown()


def retry_on_network_timeout(func, retries=3):
    """ Decorator which retries upon a network timeout """
    def wrapper(*args, **kwargs):
        for i in range(retries):
            try:
                return func(*args, **kwargs)
            except (TimeoutError, OSError):
                # OSError can be raised when creating a tor daemon
                # (should this be refactored into the tor netlayer?)
                if i == retries - 1:
                    raise
    return wrapper
