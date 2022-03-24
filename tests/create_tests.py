#!/usr/bin/env python3
import os

_dirname = os.path.dirname(os.path.abspath(__file__))

PATTERN = """
def test_{name}():
    _filename = os.path.join(_dirname, "ekyc_examples/{typ}",
                             "{file_name}")

    with open(_filename, "r") as fp:
        _info = json.loads(fp.read())
        vc = VerifiedClaims(**_info)
        
    assert vc        
"""


def create(typ):
    doc = [
        "import json",
        "import os",
        "from idpyoidc.message.oidc.identity_assurance import VerifiedClaims",
        "_dirname = os.path.dirname(os.path.abspath(__file__))"
    ]

    _root = os.path.join(_dirname, "ekyc_examples", typ)
    for _file in os.listdir(_root):
        _full_name = os.path.join(_root, _file)
        if os.path.isfile(_full_name):
            if _file.endswith('.json'):
                name = _file[:-5]
                doc.append(PATTERN.format(typ=typ, file_name=_file, name=name))

    print("\n\n".join(doc))


if __name__ == '__main__':
    create("response")
