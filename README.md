# OCapN Test suite

This repository contains a test suite for CapTP, OCapN netlayers & OCapN URIs, a work-in-progress of the OCapN Pre-Standardization Group. The goal of this test suite is to ensure compliance with the CapTP specification and facilitate interoperation between different CapTP implementations.

## Requirements

- Python 3.10 or greater,
- python-cryptography

### Tor onion netlayer

- Tor
- python-stem (https://stem.torproject.org/)

### TCP __TESTING__ netlayer

IT IS HIGHLY INSECURE, DO NOT USE IN PRODUCTION.

TCP netlayer streams pure Syrup-encoded data directly, without any encryption or metadata apart from regular CapTP messages.
It is simple to implement, and should be enough to get you through the tests.

E.g `./test_runner.py 'ocapn://a2ef69ddd5f84840970612ff660f5058.tcp-testing-only?host=127.0.0.1&port=22045'` will try to connect to port 22045 on localhost, and run tests on it.

## Testing against an implementation

To test against an implementation you must implement a set of objects located
at specific pre-defined objects. Here's the following objects you should
implement with their behavour and swiss num. The swiss numbers specified are
in ASCII.

### Car Factory builder

This takes no arguments and returns a "Car Factory" object. It should be located
at the swiss num: "JadQ0++RzsD4M+40uLxTWVaVqM10DcBJ"

### Car Factory

This takes a single argument which is a sequence, each value in the sequence
should be a list with two items:

1. a symbol representing the car model
2. a symbol representing the color of the car

It should spawn the same number of "car" objects as there are items in the
sequence and each car should be of the model and color specified in the
sequence.

### Car

This should take no arguments and respond with

"Vroom! I'm a <color> <model> car!"

Where <color> and <model> are the color and model of the car respectively.

### Echo GC

This takes any number of arguments and returns them in the same order it got
them. Importantly this will be used to test the GC so it should not retain
references and should (if possible) try to arrange so that the run the GC after
each call.

This should be available at the swiss num: "IO58l1laTyhcrgDKbEzFOO32MDd6zE5w"

### Greeter

This takes a single argument which is a reference to another object. Upon
receipt of a message it should send the greeting "Hello" (string) to the object
referenced by the argument.

This greeting should be sent as a `op:deliver` and the resulting promise should
be discarded (no references retained). The implementation should (if possible)
try to arrange so that the GC is run upon resolution of the promise.

This should be available at the swiss num: "VMDDd1voKWarCe2GvgLbxbVFysNzRPzx"

### Promise resolver

This takes no arguments and returns a promise and a resolver. When the resolver
is sent a message, the first argument should either be the symbol `break` or the
symbol `fulfill`, the other arguments should be the error or value to resolve the
promise with.

This should be available at the swiss num: "IokCxYmMj04nos2JN1TDoY1bT8dXh6Lr"

## Sturdyref enlivener

This takes a single argument which OCapN sturdyref object. The actor should
"enliven" (connect to the peer and get a live reference to the object)
the sturdyref and then return that to the messager.

This should be available at the swiss num: "gi02I1qghIwPiKGKleCQAOhpy3ZtYRpB"

## Licence

Apache 2.0 License. See the LICENSE file for details.

## Funding

This project is funded through the [NGI Assure Fund](https://nlnet.nl/assure), a fund established by [NLnet](https://nlnet.nl) with financial support from the European Commission's [Next Generation Internet](https://ngi.eu) program. Learn more on the [NLnet project page]( https://nlnet.nl/project/SpritelyOCCapN#ack).

[<img src="https://nlnet.nl/logo/banner.png" alt="NLnet foundation logo" width="20%" />](https://nlnet.nl)
[<img src="https://nlnet.nl/image/logos/NGIAssure_tag.svg" alt="NGI Assure Logo" width="20%" />](https://nlnet.nl/assure)
