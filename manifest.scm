(use-modules (gnu packages python)
             (gnu packages python-xyz)
             (gnu packages tor)
             (guix packages))

(specifications->manifest
    (list "python" "python-stem" "python-cryptography" "tor"))