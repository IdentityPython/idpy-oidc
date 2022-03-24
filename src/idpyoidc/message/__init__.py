import copy
import json
import logging
from collections.abc import MutableMapping
from urllib.parse import parse_qs
from urllib.parse import urlencode

from cryptojwt.jwe.jwe import JWE
from cryptojwt.jwe.jwe import factory as jwe_factory
from cryptojwt.jws.jws import JWS
from cryptojwt.jws.jws import factory as jws_factory
from cryptojwt.utils import as_unicode

from idpyoidc.exception import DecodeError
from idpyoidc.exception import FormatError
from idpyoidc.exception import MessageException
from idpyoidc.exception import MissingRequiredAttribute
from idpyoidc.exception import MissingSigningKey
from idpyoidc.exception import NotAllowedValue
from idpyoidc.exception import OidcMsgError
from idpyoidc.exception import TooManyValues

logger = logging.getLogger(__name__)

ERRTXT = "On '%s': %s"


class Message(MutableMapping):
    """
    Represents a basic protocol nessage/item in OAuth2/OIDC
    """

    c_param = {}
    c_default = {}
    c_allowed_values = {}

    def __init__(self, set_defaults=True, **kwargs):
        if set_defaults:
            self._dict = self.c_default.copy()
        else:
            self._dict = {}
        self.lax = False
        self.jwt = None
        self.jws_header = None
        self.jwe_header = None
        self.from_dict(kwargs)
        self.verify_ssl = True

    def __iter__(self):
        """
        Returns an iterator over all the key, value pairs in this class instance

        :return: iterator
        """
        return iter(self._dict)

    def type(self):
        """
        Return the type of protocol message this is

        :return: The name of the message
        """
        return self.__class__.__name__

    def parameters(self):
        """
        Returns a list of all known parameters for this message type.

        :return: list of parameter names
        """
        return list(self.c_param.keys())

    def set_defaults(self):
        """
        Based on specification set a parameters value to the default value.
        """
        for key, val in self.c_default.items():
            self._dict.setdefault(key, val)

    def to_urlencoded(self, lev=0):
        """
        Creates a string using the application/x-www-form-urlencoded format

        :return: A string of the application/x-www-form-urlencoded format
        """

        _spec = self.c_param
        if not self.lax:
            for attribute, (_, req, _ser, _, _) in _spec.items():
                if req and attribute not in self._dict:
                    raise MissingRequiredAttribute("%s" % attribute, "%s" % self)

        params = []

        for key, val in self._dict.items():
            try:
                (_, req, _ser, _, null_allowed) = _spec[key]
            except KeyError:  # extra attribute
                try:
                    _key = key.split("#")[0]
                    (_, req, _ser, _deser, null_allowed) = _spec[_key]
                except (ValueError, KeyError):
                    try:
                        (_, req, _ser, _, null_allowed) = _spec["*"]
                    except KeyError:
                        _ser = None
                        null_allowed = False

            if val is None and null_allowed is False:
                continue

            if isinstance(val, str):
                # Should I allow parameters with "" as value ???
                params.append((key, val.encode("utf-8")))
            elif isinstance(val, list):
                if _ser:
                    params.append((key, str(_ser(val, sformat="urlencoded", lev=lev))))
                else:
                    for item in val:
                        params.append((key, str(item).encode("utf-8")))
            elif isinstance(val, Message):
                try:
                    _val = json.dumps(_ser(val, sformat="dict", lev=lev + 1))
                    params.append((key, _val))
                except TypeError:
                    params.append((key, val))
            elif val is None:
                params.append((key, val))
            else:
                try:
                    params.append((key, _ser(val, lev=lev)))
                except Exception:
                    params.append((key, str(val)))

        try:
            return urlencode(params)
        except UnicodeEncodeError:
            _val = []
            for k, v in params:
                try:
                    _val.append((k, v.encode("utf-8")))
                except TypeError:
                    _val.append((k, v))
            return urlencode(_val)

    def serialize(self, method="urlencoded", lev=0, **kwargs):
        """
        Convert this instance to another representation. Which representation
        is given by the choice of serialization method.

        :param method: A serialization method. Presently 'urlencoded', 'json',
            'jwt' and 'dict' is supported.
        :param lev:
        :param kwargs: Extra key word arguments
        :return: THe content of this message serialized using a chosen method
        """
        return getattr(self, "to_%s" % method)(lev=lev, **kwargs)

    def deserialize(self, info, method="urlencoded", **kwargs):
        """
        Convert from an external representation to an internal.

        :param info: The input
        :param method: The method used to deserialize the info
        :param kwargs: extra Keyword arguments
        :return: In the normal case the Message instance
        """
        try:
            func = getattr(self, "from_%s" % method)
        except AttributeError:
            raise FormatError("Unknown serialization method (%s)" % method)
        else:
            return func(info, **kwargs)

    def from_urlencoded(self, urlencoded, **kwargs):
        """
        Starting with a string of the application/x-www-form-urlencoded format
        this method creates a class instance

        :param urlencoded: The string
        :return: A class instance or raise an exception on error
        """

        # parse_qs returns a dictionary with keys and values. The values are
        # always lists even if there is only one value in the list.
        # keys only appears once.

        if isinstance(urlencoded, str):
            pass
        elif isinstance(urlencoded, list):
            urlencoded = urlencoded[0]

        _spec = self.c_param

        _info = parse_qs(urlencoded)
        if len(urlencoded) and _info == {}:
            raise FormatError("Wrong format")

        for key, val in _info.items():
            try:
                (typ, _, _, _deser, _) = _spec[key]
            except KeyError:
                try:
                    _key = key.split("#")[0]
                    (typ, _, _, _deser, _) = _spec[_key]
                except (ValueError, KeyError):
                    try:
                        (typ, _, _, _deser, _) = _spec["*"]
                    except KeyError:
                        if len(val) == 1:
                            val = val[0]

                        self._dict[key] = val
                        continue

            if isinstance(typ, list):
                if _deser:
                    self._dict[key] = _deser(val[0], "urlencoded")
                else:
                    self._dict[key] = val
            else:  # must be single value
                if len(val) == 1:
                    if _deser:
                        self._dict[key] = _deser(val[0], "urlencoded")
                    elif isinstance(val[0], typ):
                        self._dict[key] = val[0]
                    else:
                        self._dict[key] = val[0]
                else:
                    raise TooManyValues("{}".format(key))

        return self

    def to_dict(self, lev=0):
        """
        Return a dictionary representation of the class

        :return: A dict
        """

        _spec = self.c_param

        _res = {}
        lev += 1
        for key, val in self._dict.items():
            try:
                _ser = _spec[str(key)][2]
            except KeyError:
                try:
                    _key = key.split("#")[0]
                    _ser = _spec[_key][2]
                except (ValueError, KeyError):
                    try:
                        _ser = _spec["*"][2]
                    except KeyError:
                        _ser = None

            if _ser:
                val = _ser(val, "dict", lev)

            if isinstance(val, Message):
                _res[key] = val.to_dict(lev + 1)
            elif isinstance(val, list) and isinstance(next(iter(val or []), None), Message):
                _res[key] = [v.to_dict(lev) for v in val]
            else:
                _res[key] = val

        return _res

    def from_dict(self, dictionary, **kwargs):
        """
        Direct translation, so the value for one key might be a list or a
        single value.

        :param dictionary: The info
        :return: A class instance or raise an exception on error
        """

        _spec = self.c_param

        for key, val in dictionary.items():
            # Earlier versions of python don't like unicode strings as
            # variable names
            if val in ["", [""]]:
                continue

            skey = str(key)
            try:
                (vtyp, _, _, _deser, null_allowed) = _spec[key]
            except KeyError:
                # might be a parameter with a lang tag
                try:
                    _key = skey.split("#")[0]
                except ValueError:
                    try:
                        (vtyp, _, _, _deser, null_allowed) = _spec["*"]
                        if val is None:
                            self._dict[key] = val
                            continue
                    except KeyError:
                        self._dict[key] = val
                        continue
                else:
                    try:
                        (vtyp, _, _, _deser, null_allowed) = _spec[_key]
                    except KeyError:
                        try:
                            (vtyp, _, _, _deser, null_allowed) = _spec["*"]
                            if val is None:
                                self._dict[key] = val
                                continue
                        except KeyError:
                            self._dict[key] = val
                            continue

            self._add_value(skey, vtyp, key, val, _deser, null_allowed, sformat="dict")
        return self

    def _add_value(self, skey, vtyp, key, val, _deser, null_allowed, sformat="urlencoded"):
        """
        Main method for adding a value to the instance. Does all the
        checking on type of value and if among allowed values.

        :param skey: string version of the key
        :param vtyp: Type of value
        :param key: original representation of the key
        :param val: The value to add
        :param _deser: A deserializer for this value type
        :param null_allowed: Whether null is an allowed value for this key
        """

        if isinstance(val, list):
            if (len(val) == 0 or val[0] is None) and null_allowed is False:
                return

        if isinstance(vtyp, tuple):
            vtyp = vtyp[0]

        if isinstance(vtyp, list):
            if val is None:
                if null_allowed:
                    self._dict[key] = val
                    return
                raise ValueError("Null is not allowed")

            vtype = vtyp[0]
            if isinstance(val, vtype):
                if issubclass(vtype, Message):
                    self._dict[skey] = [val]
                elif _deser:
                    try:
                        self._dict[skey] = _deser(val, sformat=sformat)
                    except Exception as exc:
                        raise DecodeError(ERRTXT % (key, exc))
                else:
                    setattr(self, skey, [val])
            elif isinstance(val, list):
                if _deser:
                    try:
                        val = _deser(val, sformat="dict")
                    except Exception as exc:
                        raise DecodeError(ERRTXT % (key, exc))

                if issubclass(vtype, Message):
                    try:
                        _val = []
                        for v in val:
                            _val.append(vtype(**{str(x): y for x, y in v.items()}))
                        val = _val
                    except Exception as exc:
                        raise DecodeError(ERRTXT % (key, exc))
                else:
                    for v in val:
                        if not isinstance(v, vtype):
                            raise DecodeError(ERRTXT % (key, "type != %s (%s)" % (vtype, type(v))))

                self._dict[skey] = val
            elif isinstance(val, dict):
                try:
                    val = _deser(val, sformat="dict")
                except Exception as exc:
                    raise DecodeError(ERRTXT % (key, exc))
                else:
                    self._dict[skey] = val
            else:
                raise DecodeError(ERRTXT % (key, "type != %s" % vtype))
        else:
            if val is None:
                self._dict[skey] = None
            elif isinstance(val, bool):
                if vtyp is bool:
                    self._dict[skey] = val
                else:
                    raise ValueError('"{}", wrong type of value for "{}"'.format(val, skey))
            elif isinstance(val, vtyp):  # Not necessary to do anything
                self._dict[skey] = val
            else:
                if _deser:
                    try:
                        val = _deser(val, sformat="dict")
                    except Exception as exc:
                        raise DecodeError(ERRTXT % (key, exc))
                    else:
                        self._dict[skey] = val
                elif vtyp is int:
                    try:
                        self._dict[skey] = int(val)
                    except (ValueError, TypeError):
                        raise ValueError('"{}", wrong type of value for "{}"'.format(val, skey))
                elif vtyp is bool:
                    raise ValueError('"{}", wrong type of value for "{}"'.format(val, skey))
                elif vtyp != type(val):
                    if vtyp == Message:
                        if isinstance(val, (dict, str)):
                            self._dict[skey] = val
                        else:
                            raise ValueError('"{}", wrong type of value for "{}"'.format(val, skey))
                    else:
                        raise ValueError('"{}", wrong type of value for "{}"'.format(val, skey))

    def to_json(self, lev=0, indent=None):
        """
        Serialize the content of this instance into a JSON string.

        :param lev:
        :param indent: Number of spaces that should be used for indentation
        :return:
        """
        if lev:
            return self.to_dict(lev + 1)
        else:
            return json.dumps(self.to_dict(1), indent=indent)

    def from_json(self, txt, **kwargs):
        """
        Convert from a JSON string to an instance of this class.

        :param txt: The JSON string (a ``str``, ``bytes`` or ``bytearray``
            instance containing a JSON document)
        :param kwargs: extra keyword arguments
        :return: The instantiated instance
        """
        _dict = json.loads(txt)
        return self.from_dict(_dict)

    def to_jwt(self, key=None, algorithm="", lev=0, lifetime=0):
        """
        Create a signed JWT representation of the class instance

        :param key: The signing key
        :param algorithm: The signature algorithm to use
        :param lev:
        :param lifetime: The lifetime of the JWS
        :return: A signed JWT
        """

        _jws = JWS(self.to_json(lev), alg=algorithm)
        return _jws.sign_compact(key)

    def _gather_keys(self, keyjar, jwt, header, **kwargs):
        key = []

        if keyjar:
            _keys = keyjar.get_jwt_verify_keys(jwt, **kwargs)
            if not _keys:
                keyjar.update()
                _keys = keyjar.get_jwt_verify_keys(jwt, **kwargs)
            key.extend(_keys)

        if "alg" in header and header["alg"] != "none":
            if not key:
                if keyjar:
                    keyjar.update()
                    key = keyjar.get_jwt_verify_keys(jwt, **kwargs)
                    if not key:
                        raise MissingSigningKey("alg=%s" % header["alg"])
                else:
                    raise MissingSigningKey("alg=%s" % header["alg"])

        return key

    def from_jwt(self, txt, keyjar, verify=True, **kwargs):
        """
        Given a signed and/or encrypted JWT, verify its correctness and then
        create a class instance from the content.

        :param txt: The JWT
        :param key: keys that might be used to decrypt and/or verify the
            signature of the JWT
        :param verify: Whether the signature should be verified or not
        :param keyjar: A KeyJar that might contain the necessary key.
        :param kwargs: Extra key word arguments
        :return: A class instance
        """

        algarg = {}
        if "encalg" in kwargs:
            algarg["alg"] = kwargs["encalg"]
        if "encenc" in kwargs:
            algarg["enc"] = kwargs["encenc"]
        _decryptor = jwe_factory(txt, **algarg)

        if _decryptor:
            logger.debug("JWE headers: %s", _decryptor.jwt.headers)

            dkeys = keyjar.get_decrypt_key(owner="")

            logger.debug("Decrypt class: %s", _decryptor.__class__)
            _res = _decryptor.decrypt(txt, dkeys)
            logger.debug("decrypted message: %s", _res)
            if isinstance(_res, tuple):
                txt = as_unicode(_res[0])
            elif isinstance(_res, list) and len(_res) == 2:
                txt = as_unicode(_res[0])
            else:
                txt = as_unicode(_res)
            self.jwe_header = _decryptor.jwt.headers

        if kwargs.get("sigalg"):
            _verifier = jws_factory(txt, alg=kwargs["sigalg"])
        else:
            _verifier = jws_factory(txt)

        if _verifier:
            _jwt = _verifier.jwt
            jso = _jwt.payload()
            _header = _jwt.headers

            # if "sender" in kwargs:
            #     key.extend(keyjar.get_verify_key(owner=kwargs["sender"]))

            logger.debug("Raw JSON: %s", jso)
            logger.debug("JWS header: %s", _header)
            if _header["alg"] == "none":
                pass
            elif verify:
                key = self._gather_keys(keyjar, _jwt, _header, **kwargs)

                if not key:
                    raise MissingSigningKey("alg=%s" % _header["alg"])

                logger.debug("Found signing key.")
                _verifier.verify_compact(txt, key)

            self.jws_header = _jwt.headers
        else:
            jso = json.loads(txt)

        self.jwt = txt
        return self.from_dict(jso)

    def __str__(self):
        """
        Return a string representation of this class

        :return: A string representation of this class
        """
        return "{}".format(self.to_dict())

    @staticmethod
    def _type_check(typ, _allowed, val, na=False):
        if typ is str:
            if val not in _allowed:
                return False
        elif typ is int:
            if val not in _allowed:
                return False
        elif isinstance(typ, list):
            if isinstance(val, list):
                # _typ = typ[0]
                for item in val:
                    if item not in _allowed:
                        return False
        elif val is None and na is False:
            return False
        return True

    def verify(self, **kwargs):
        """
        Make sure all the required values are there and that the values are
        of the correct type
        """
        _spec = self.c_param
        try:
            _allowed = self.c_allowed_values
        except KeyError:
            _allowed = {}

        for (attribute, (typ, required, _, _, na)) in _spec.items():
            if attribute == "*":
                continue

            try:
                val = self._dict[attribute]
            except KeyError:
                if required:
                    raise MissingRequiredAttribute("%s" % attribute)
                continue
            else:
                if typ == bool:
                    pass
                elif not val:
                    if required:
                        raise MissingRequiredAttribute("%s" % attribute)
                    continue

            try:
                _allowed_val = _allowed[attribute]
            except KeyError:
                pass
            else:
                if not self._type_check(typ, _allowed_val, val, na):
                    raise NotAllowedValue(val)

        return True

    def keys(self):
        """
        Return a list of attribute/keys/parameters of this class that has
        values.

        :return: A list of attribute names
        """
        return self._dict.keys()

    def __getitem__(self, item):
        """
        Return the value of a specified parameter.

        :param item:
        :return:
        """
        return self._dict[item]

    def get(self, item, default=None):
        """
        Return the value of a specific parameter. If the parameter does not
        have a value return the default value.

        :param item: The name of the parameter
        :param default: Default value
        :return: The value of the parameter or, if that doesn't exist,
            the default value
        """
        try:
            return self[item]
        except KeyError:
            return default

    def items(self):
        """
        Return a list of tuples (key, value) representing all parameters
        of this class instance that has a value.

        :return: iterator
        """
        return self._dict.items()

    def values(self):
        return self._dict.values()

    def __contains__(self, item):
        """
        Answers the question: does this parameter have a value?

        :param item: The name of the parameter
        :return: True/False
        """
        return item in self._dict

    def request(self, location, fragment_enc=False):
        """
        Given a URL this method will add a fragment, a query part or extend
        a query part if it already exists with the information in this instance.

        :param location: A URL
        :param fragment_enc: Whether the information should be placed in a
            fragment (True) or in a query part (False)
        :return: The extended URL
        """
        _l = as_unicode(location)
        _qp = as_unicode(self.to_urlencoded())
        if fragment_enc:
            return "%s#%s" % (_l, _qp)
        else:
            if "?" in location:
                return "%s&%s" % (_l, _qp)
            else:
                return "%s?%s" % (_l, _qp)

    def __setitem__(self, key, value):
        try:
            (vtyp, req, _, _deser, na) = self.c_param[key]
            self._add_value(str(key), vtyp, key, value, _deser, na)
        except KeyError:
            self._dict[key] = value

    def __eq__(self, other):
        """
        Compare two message instances. This with another instance.

        :param other:  The other instance
        :return: True/False
        """
        if not isinstance(other, Message):
            return False
        if self.type() != other.type():
            return False

        if self._dict != other._dict:
            return False

        return True

    # def __getattr__(self, item):
    #        return self._dict[item]

    def __delitem__(self, key):
        del self._dict[key]

    def __len__(self):
        """
        Return the number of parameters that has a value.

        :return: Number of parameters with a value.
        """
        return len(self._dict)

    def extra(self):
        """
        Return the extra parameters that this instance contains. Extra meaning those
        that are not listed in the c_params specification.

        :return: The key,value pairs for keys that are not in the c_params
            specification,
        """
        return dict([(key, val) for key, val in self._dict.items() if key not in self.c_param])

    def only_extras(self):
        """
        Return True if this instance only has key,value pairs for keys
        that are not defined in c_params.

        :return: True/False
        """
        known = [key for key in self._dict.keys() if key in self.c_param]
        if not known:
            return True
        else:
            return False

    def update(self, item, **kwargs):
        """
        Update the information in this instance.

        :param item: a dictionary or a Message instance
        """
        if isinstance(item, dict):
            self._dict.update(item)
        elif isinstance(item, Message):
            for key, val in item.items():
                self._dict[key] = val
        else:
            raise ValueError("Can't update message using: '%s'" % (item,))

    def to_jwe(self, keys, enc, alg, lev=0):
        """
        Place the information in this instance in a JSON object. Make that
        JSON object the body of a JWT. Then encrypt that JWT using the
        specified algorithms and the given keys. Return the encrypted JWT.

        :param keys: list or KeyJar instance
        :param enc: Content Encryption Algorithm
        :param alg: Key Management Algorithm
        :param lev: Used for JSON construction
        :return: An encrypted JWT. If encryption failed an exception will be
            raised.
        """

        _jwe = JWE(self.to_json(lev), alg=alg, enc=enc)
        return _jwe.encrypt(keys)

    def from_jwe(self, msg, keys):
        """
        Decrypt an encrypted JWT and load the JSON object that was the body
        of the JWT into this object.

        :param msg: An encrypted JWT
        :param keys: Possibly usable keys.
        :type keys: list or KeyJar instance
        :return: The decrypted message. If decryption failed an exception
            will be raised.
        """

        jwe = JWE()
        _res = jwe.decrypt(msg, keys)
        return self.from_json(_res.decode())

    def copy(self):
        return copy.deepcopy(self)

    def weed(self):
        """
        Get rid of key value pairs that are not standard
        """
        _ext = [k for k in self._dict.keys() if k not in self.c_param]
        for k in _ext:
            del self._dict[k]

    def rm_blanks(self):
        """
        Get rid of parameters that has no value.
        """
        _blanks = [k for k in self._dict.keys() if not self._dict[k]]
        for key in _blanks:
            del self._dict[key]

    def required_parameters(self):
        """
        Return the required parameters for this type of message.
        """
        return [p for p, s in self.c_param.items() if s[1] is True]

    def value_type(self, parameter):
        """
        Return the type of value that a parameter can have.

        :param parameter: Name of the parameter
        :return: Type of Value or None if unknown.
        """
        _spec = self.c_param.get(parameter)
        if _spec:
            return _spec[0]

        return None

    def has_none_or_one_of(self, claims):
        found_one = False
        for c in claims:
            if c in self:
                if found_one:
                    return False
                else:
                    found_one = True
        return True

# =============================================================================


def by_schema(cls, **kwa):
    return dict([(key, val) for key, val in kwa.items() if key in cls.c_param])


def add_non_standard(msg1, msg2):
    for key, val in msg2.extra().items():
        if key not in msg1.c_param:
            msg1[key] = val


# =============================================================================


def list_serializer(vals, sformat="urlencoded", lev=0):
    if isinstance(vals, str) and sformat == "dict":
        return [vals]

    if not isinstance(vals, list):
        raise ValueError("Expected list: %s" % vals)

    if sformat == "urlencoded":
        return " ".join(vals)
    else:
        return vals


def list_deserializer(val, sformat="urlencoded"):
    if sformat == "urlencoded":
        if isinstance(val, str):
            return val.split(" ")
        elif isinstance(val, list) and len(val) == 1:
            return val[0].split(" ")
    elif sformat == "dict":
        if isinstance(val, str):
            val = [val]

    return val


def sp_sep_list_serializer(vals, sformat="urlencoded", lev=0):
    if isinstance(vals, str):
        return vals
    else:
        return " ".join(vals)


def sp_sep_list_deserializer(val, sformat="urlencoded"):
    if isinstance(val, str):
        return val.split(" ")
    elif isinstance(val, list) and len(val) == 1:
        return val[0].split(" ")
    else:
        return val


def json_serializer(obj, sformat="urlencoded", lev=0):
    return json.dumps(obj)


def json_deserializer(txt, sformat="urlencoded"):
    return json.loads(txt)


def msg_deser(val, sformat="urlencoded"):
    if isinstance(val, Message):
        return val
    elif sformat in ["dict", "json"]:
        if not isinstance(val, str):
            val = json.dumps(val)
            sformat = "json"
    return Message().deserialize(val, sformat)


def msg_ser(inst, sformat, lev=0):
    if sformat in ["urlencoded", "json"]:
        if isinstance(inst, dict):
            if sformat == "json":
                res = json.dumps(inst)
            else:
                res = urlencode([(k, v) for k, v in inst.items()])
        elif isinstance(inst, Message):
            res = inst.serialize(sformat, lev)
        else:
            res = inst
    elif sformat == "dict":
        if isinstance(inst, Message):
            res = inst.serialize(sformat, lev)
        elif isinstance(inst, dict):
            res = inst
        elif isinstance(inst, str):  # Iff ID Token
            res = inst
        else:
            raise MessageException("Wrong type: %s" % type(inst))
    else:
        raise OidcMsgError("Unknown sformat", inst)

    return res


def msg_list_deser(val, sformat="urlencoded", lev=0):
    if isinstance(val, dict):
        return [Message(**val)]

    _res = []
    for v in val:
        _res.append(msg_deser(v, sformat))
    return _res


def msg_list_ser(val, sformat="urlencoded", lev=0):
    _res = []
    for v in val:
        _res.append(msg_ser(v, sformat))
    return _res


VTYPE = 0
VREQUIRED = 1
VSER = 2
VDESER = 3
VNULLALLOWED = 4

SINGLE_REQUIRED_STRING = (str, True, None, None, False)
SINGLE_OPTIONAL_STRING = (str, False, None, None, False)
SINGLE_OPTIONAL_INT = (int, False, None, None, False)
SINGLE_REQUIRED_INT = (int, True, None, None, False)
SINGLE_REQUIRED_BOOLEAN = (bool, True, None, None, False)

OPTIONAL_LIST_OF_STRINGS = ([str], False, list_serializer, list_deserializer, False)
REQUIRED_LIST_OF_STRINGS = ([str], True, list_serializer, list_deserializer, False)
OPTIONAL_LIST_OF_SP_SEP_STRINGS = (
    [str],
    False,
    sp_sep_list_serializer,
    sp_sep_list_deserializer,
    False,
)
REQUIRED_LIST_OF_SP_SEP_STRINGS = (
    [str],
    True,
    sp_sep_list_serializer,
    sp_sep_list_deserializer,
    False,
)
SINGLE_OPTIONAL_JSON = (dict, False, json_serializer, json_deserializer, False)

SINGLE_REQUIRED_JSON = (dict, True, json_serializer, json_deserializer, False)

REQUIRED = [SINGLE_REQUIRED_STRING, REQUIRED_LIST_OF_STRINGS, REQUIRED_LIST_OF_SP_SEP_STRINGS]

OPTIONAL_MESSAGE = (Message, False, msg_ser, msg_deser, False)
REQUIRED_MESSAGE = (Message, True, msg_ser, msg_deser, False)

OPTIONAL_LIST_OF_MESSAGES = ([Message], False, msg_list_ser, msg_list_deser, False)


def any_ser(val, sformat="urlencoded", lev=0):
    if isinstance(val, (str, int, bool)):
        return val
    elif isinstance(val, Message):
        return msg_ser(val, sformat, lev)
    elif isinstance(val, dict):
        return json.dumps(val)
    elif isinstance(val, list):
        return msg_list_ser(val)
    else:
        raise ValueError("Can't serialize this type of data")


def any_deser(val, sformat="urlencoded", lev=0):
    if isinstance(val, dict):
        return Message(**val)
    elif isinstance(val, list):
        return [msg_deser(v, sformat) for v in val]
    else:
        raise ValueError("Can't deserialize this type of data")


SINGLE_OPTIONAL_ANY = (any, False, any_ser, any_deser, False)
REQUIRED_LIST_OF_DICTS = ([dict], True, list_serializer, list_deserializer, False)
OPTIONAL_LIST_OF_DICTS = ([dict], False, list_serializer, list_deserializer, False)
