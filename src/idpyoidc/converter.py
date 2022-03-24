# Message class to pydantic class converter

def get_type(typ) -> str:
    if typ == str:
        return "str"
    elif typ == int:
        return "int"
    elif typ == dict:
        return "dict"
    elif typ == any:
        return "any"
    else:
        return typ.__name__


def convert(cls):
    res = []
    res.append("class {}(BaseModel):".format(cls.__name__))

    #     c_allowed_values = {}
    keys = list(cls.c_param.keys())
    keys.sort()

    for key in keys:
        (typ, req, _, _, _) = cls.c_param[key]
        if isinstance(typ, list):
            lt = get_type(typ[0])
            _type = f"List[{lt}]"
        else:
            lt = get_type(typ)
            _type = f"{lt}"

        if not req:
            _type = f"Optional[{_type}]"

        if key in cls.c_default:
            default = cls.c_default[key]
            res.append(f"    {key}: {_type} = '{default}'")
        else:
            res.append(f"    {key}: {_type}")

    return res
