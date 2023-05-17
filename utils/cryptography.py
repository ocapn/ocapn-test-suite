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

from contrib.syrup import Symbol, syrup_encode
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

class Crypto:
    """ Add methods for working with CapTP cryptography """

    def _generate_key(self):
        """ Generate a new ed25519 keypair """
        private_key = Ed25519PrivateKey.generate()
        return private_key.public_key(), private_key

    def _sign(self, data, private_key):
        """ Sign some data using the given private key """
        return private_key.sign(data)
    
    def _verify(self, data, signature, public_key):
        """ Verify a signature using the given public key """
        return public_key.verify(signature, data)

    def _key_pair_to_captp(self, private_key):
        """ Converts a key pair to the CapTP format """
        # Convert to: (public-key (ecc (curve Ed25519) (flags eddsa) (q ,data)))
        q = private_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw
        )
        return [
            Symbol("public-key"),
            [
                Symbol("ecc"),
                [Symbol("curve"), Symbol("Ed25519")],
                [Symbol("flags"), Symbol("eddsa")],
                [Symbol("q"), q],
            ]
        ]
    
    def _captp_to_key_pair(self, captp_key_pair) -> Ed25519PublicKey:
        """ Converts a CapTP key pair to the cryptography library format """
        # Convert from: (public-key (ecc (curve Ed25519) (flags eddsa) (q ,data)))
        data_section = captp_key_pair[1][-1][-1]
        return Ed25519PublicKey.from_public_bytes(data_section)
    
    def _captp_to_signature(self, captp_signature) -> bytes:
        """ Converts a CapTP signature to the cryptography library format """
        # Convert from: (sig-val (eddsa (r ,r) (s ,s)))
        r = captp_signature[1][1][1]
        s = captp_signature[1][2][1]

        r_padding = bytearray(32 - len(r))
        s_padding = bytearray(32 - len(s))
        return r + r_padding + s + s_padding


