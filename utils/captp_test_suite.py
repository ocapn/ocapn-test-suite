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

class CapTPTestRunner(unittest.TextTestRunner):
    
    def __init__(self, netlayer, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.netlayer = netlayer

    def loadTests(self):
        suite = unittest.defaultTestLoader.discover("tests")
        return CapTPTestSuite(self.netlayer, suite)

class CapTPTestSuite(unittest.TestSuite):
    """ Custom test suite for CapTP which takes a netlayer to communicate over """

    def __init__(self, netlayer, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for test in self:
            if isinstance(test, CapTPTestCase):
                test.netlayer_obj = netlayer

class CapTPTestCase(unittest.TestCase):
    """ Base class for all CapTP tests """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.netlayer = None

    def setUp(self) -> None:
        self.netlayer().connect()
        return super().setUp()