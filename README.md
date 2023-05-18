# OCapN Test suite

This repository contains a test suite for CapTP, OCapN netlayers & OCapN URIs, a work-in-progress of the OCapN Pre-Standardization Group. The goal of this test suite is to ensure compliance with the CapTP specification and facilitate interoperation between different CapTP implementations.

## Requirements

- Python 3.6 or greater,
- python-cryptography

### Tor onion netlayer

- Tor
- python-stem (https://stem.torproject.org/)

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
them. Importantely this will be used to test the GC so it should not retain
references and should (if possible) try to arrange so that the run the GC after
each call.

This should be available at the swiss num: "IO58l1laTyhcrgDKbEzFOO32MDd6zE5w"

### Greeter

This takes a single argument which is a reference to another object. Upon
receipt of a message it should send the greeting "Hello" (string) to the object
referenced by the argument.

This should be available at the swiss num: "VMDDd1voKWarCe2GvgLbxbVFysNzRPzx"

### Promise resolver

This takes no arguments and returns a promise and a resolver. When the resolver
is sent a message, the first argument should either be the symbol `break` or the
symbol `fulfill`, the other arguments should be the error or value to resole the
promise with.

This should be available at the swiss num: "IokCxYmMj04nos2JN1TDoY1bT8dXh6Lr"

## Licence

Apache 2.0 License. See the LICENSE file for details.
