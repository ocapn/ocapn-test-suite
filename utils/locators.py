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

import re

class Locator:
    """ Locator address for OCapN machines
    
    These have the format ocapn://<address>.<transport>"""

    VALID_OCAPN_ADDRESS = re.compile(r'^ocapn:\/\/[a-zA-Z0-9-._]+\.[a-zA-Z0-9]+$')

    def __init__(self, locator):
        self._locator = locator

    def __str__(self):
        return self._locator
    
    def validate(self) -> bool:
        return self.VALID_OCAPN_ADDRESS.match(self._locator) is not None

    @property
    def address(self) -> str:
        # First remove the ocapn:// prefix, then take all but the last part.
        return self._locator[8:].rsplit('.', 1)[0]

    @property
    def transport(self) -> str:
        return self._locator.rsplit('.', 1)[1]
    

