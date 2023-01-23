# Persistent Storage

IdpyOIDC does not handle persistent storage per se.

It can gather information that should be put in persistent storage and it 
can apply stored information to a running instance.

All this hinges on the base class ImpExp

```
class ImpExp:
    parameter = {}
    special_load_dump = {}
    init_args = []

    def __init__(self):
        pass
```

ImpExp has three methods you should know about:

```Python
dump(self, exclude_attributes: Optional[List[str]] = None) -> dict
```

```Python
load(self,
     item: dict,
     init_args: Optional[dict] = None,
     load_args: Optional[dict] = None)
```
and

```Python
flush(self)
```

dump() produces a dictionary that can be fed into json.dumps(). 

## Simple Example

```Python
import json
from idpyoidc.impexp import ImpExp
from idpyoidc.message.oauth2 import ResponseMessage
from idpyoidc.message.oidc import UserInfoErrorResponse


class SimpleExample(ImpExp):
    parameter = {
        "foo": "",
        "message": ResponseMessage
    }


example = SimpleExample()
example.foo = "bar"
response = ResponseMessage(error='invalid_request',
                           error_description='Unsupported parameter value')
example.cls = UserInfoErrorResponse(**response.to_dict())

print(json.dumps(example.dump(), indent=4, sort_keys=True))
```

The output of this small program should be:

```Python
{
    "foo": "bar",
    "message": {
        "idpyoidc.message.oidc.UserInfoErrorResponse": {
            "error": "invalid_request",
            "error_description": "Unsupported parameter value"
        }
    }
}
```



### parameter

Contains a list of all the parameters that can be dumped/loaded and their types.
The following types are recognized.
The simple ones:
- None
- 0
- ""
- []
- {}
- bool
- b""
- object

and the more complex:

- Message
- DICT_TYPE
- [\<type\>]

If there is a type definition that ImpExp does not recognize it will just try

```
item.dump(exclude_attributes=exclude_attributes)
```

### init_args

### special_load_dump

