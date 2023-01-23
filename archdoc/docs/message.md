# The Message Class

The message class contains definitions of:

- The expected set of claims
- The Claim value types
- Which claims are Optional or which are Required
- If there is a default value for a claim

A message class instance:

- Behaves as a dictionary
- Can serialize and deserialize requests/responses to and from a number of formats

## Parameters

There are three
- c_param
- c_default
- c_allowed_values


### c_param

One of the basic subclasses of Message will provide us with a bases for a
walk-through of what a message definition looks like.

```Python
class ResponseMessage(Message):
    """
    The basic error response
    """

    c_param = {
        "error": SINGLE_OPTIONAL_STRING,
        "error_description": SINGLE_OPTIONAL_STRING,
        "error_uri": SINGLE_OPTIONAL_STRING,
    }

    def verify(self, **kwargs):
        super(ResponseMessage, self).verify(**kwargs)
        if "error_description" in self:
            # Verify that the characters used are within the allowed ranges
            # %x20-21 / %x23-5B / %x5D-7E
            if not all(x in error_chars for x in self["error_description"]):
                raise ValueError("Characters outside allowed set")
        return True
```

The **c_param** parameter contains the names of the claims that are expected
to be in the message and for each of these claims the value definition.

A value definition can look like this:

```Python
SINGLE_OPTIONAL_STRING = (str, False, None, None, False)
```

It is a tuple containing these parts:
- value type of the parameter in the Message instance
- Required or not
- deserialization function
- serialization function
- If the claim is allowed to have a null value

To take another example:

```Python
SINGLE_REQUIRED_JSON = (dict, True, json_serializer, json_deserializer, False)
```

Here the value of the claim in the message instance is expected to be a dictionary.
The serializer function is then simple expressed as:

```Python
def json_serializer(obj, sformat="urlencoded", lev=0):
    return json.dumps(obj)
```

A last example to show how a more complex type is expressed:

```
REQUIRED_LIST_OF_DICTS = ([dict], True, list_serializer, list_deserializer, False)
```

The base set of claim definitions:

- OPTIONAL_LIST_OF_STRINGS
- OPTIONAL_LIST_OF_SP_SEP_STRINGS
- OPTIONAL_MESSAGE
- OPTIONAL_LIST_OF_MESSAGES
- OPTIONAL_LIST_OF_DICTS 
- REQUIRED_LIST_OF_DICTS 
- REQUIRED_LIST_OF_STRINGS
- REQUIRED_LIST_OF_SP_SEP_STRINGS
- REQUIRED_MESSAGE
- SINGLE_OPTIONAL_ANY 
- SINGLE_OPTIONAL_STRING
- SINGLE_OPTIONAL_INT
- SINGLE_OPTIONAL_JSON
- SINGLE_REQUIRED_BOOLEAN
- SINGLE_REQUIRED_INT
- SINGLE_REQUIRED_JSON

**NOTE**: Message allows claims that are not in the c_param list but are in that case 
not able to verify the value/-s.

### c_default

This matters for deserialization. If there is no claim value for the specified claim in
the information then this value is added after the deserialization.

```
class CCAccessTokenRequest(Message):
    """
    Client Credential grant flow access token request
    """

    c_param = {"grant_type": SINGLE_REQUIRED_STRING, "scope": OPTIONAL_LIST_OF_SP_SEP_STRINGS}
    c_default = {"grant_type": "client_credentials"}
    c_allowed_values = {"grant_type": ["client_credentials"]}
```

### c_allowed_values

If the values of a claim is limited to a specific set of values.

## Serialization/Deserialization

The base Message class contains a number of serializing/deserializing methods:

- to/from_dict
- to/from_urlencoded
- to/from_json
- to/from_jwt
- to/from_jwe

The overall definition of a serializer is:

```
def serializer(obj: Union[Message, dict, str], 
               sformat: Optional[str] = 'urlencoded', 
               lev: Optional[int] = 0) -> Union[str, dict]:
    """
    :param obj: The object to serialize
    :param sformat: A serialization method. Presently 'urlencoded', 'json',
            'jwt' and 'dict' is supported.
    :param lev: Legacy parameter, not used 
    :returns: In the case of 'urlencoded','json' or 'jwt' a string else a dictionary
```

### Example

```Python
class DummyMessage(Message):
    c_param = {
        "req_str": SINGLE_REQUIRED_STRING,
        "opt_str": SINGLE_OPTIONAL_STRING,
        "opt_int": SINGLE_OPTIONAL_INT,
        "opt_str_list": OPTIONAL_LIST_OF_STRINGS,
        "req_str_list": REQUIRED_LIST_OF_STRINGS,
        "opt_json": SINGLE_OPTIONAL_JSON,
    }
```

> print(DummyMessage(req_str="Fair", 
                     req_str_list=["game"]).request("http://example.com"))
"http://example.com?req_str=Fair&req_str_list=game"

## verify()

The method that is used to verify whether the parameters of a message instance 
follows the boundaries define in **c_params**.

The base class (Message) does all the checking of the claims, if they are present 
of the right type and so forth.

What verify() has to do is additional tests

