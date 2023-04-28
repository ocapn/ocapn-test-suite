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

from utils.cryptography import Crypto

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

    def loadTests(self):
        loader = CapTPTestLoader(self.netlayer)
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