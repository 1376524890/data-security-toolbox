"""Masked samples for hits that are reported without their original text.

The rule store (``rule_library.scan_managed``) and the network DLP stage both
list a masked sample next to a hit count. The helper lives in its own module and
not in either of them, so the two do not have to import each other for one line
of formatting: an imported rule meant a network-DLP import, and the network DLP
stage imports the rule store for its confidence bounds.
"""


def masked(value):
    return value[:2] + '***' + value[-2:] if len(value) >= 6 else '***'
