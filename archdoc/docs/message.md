# The Message Class

- Defines expected set of claims
- Claim value types
- Whether claims are Optional or Required
- If there is a default value for a claim
- Behaves as a dictionary
- Can serialize and deserialize to and from a number of formats

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

```Python
SINGLE_OPTIONAL_STRING = (str, False, None, None, False)
```