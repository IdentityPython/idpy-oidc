import base64
from typing import Any
from typing import List
from typing import Optional

from cryptojwt.utils import importer
from cryptojwt.utils import qualified_name

# from idpyoidc.item import DLDict
from idpyoidc.message import Message
from idpyoidc.storage import DictType


def fully_qualified_name(cls):
    return cls.__module__ + "." + cls.__class__.__name__


def type2cls(v):
    if isinstance(v, str):
        return ""
    elif isinstance(v, int):
        return 0
    elif isinstance(v, bool):
        return bool
    elif isinstance(v, bytes):
        return b""
    elif isinstance(v, dict):
        return {}
    elif isinstance(v, list):
        return []
    else:
        return None


class ImpExp:
    parameter = {}
    special_load_dump = {}
    init_args = []

    def __init__(self):
        pass

    def dump_attr(self, cls, item, exclude_attributes: Optional[List[str]] = None) -> dict:
        if cls in [None, 0, "", bool]:
            val = item
        elif cls == b"":
            val = f"BYTES:{base64.b64encode(item).decode('utf-8')}"
        elif cls == {} and isinstance(item, dict):
            val = {}
            for k, v in item.items():
                if k != "upstream_get":
                    if k == "class":
                        if isinstance(v, str):
                            val[k] = v
                        else:
                            val[k] = fully_qualified_name(v)
                    else:
                        val[k] = self.dump_attr(type2cls(v), v, exclude_attributes)
        elif cls == [] and isinstance(item, list):
            val = [self.dump_attr(type2cls(v), v, exclude_attributes) for v in item]
        elif cls == "DICT_TYPE":
            if isinstance(item, dict):
                val = item
            else:
                if isinstance(item, DictType):  # item should be a class instance
                    val = {
                        "DICT_TYPE": {"class": fully_qualified_name(item), "kwargs": item.kwargs}
                    }
                else:
                    raise ValueError("Expected a DictType class")
        elif isinstance(item, Message):
            val = {qualified_name(item.__class__): item.to_dict()}
        elif cls == object:
            val = qualified_name(item)
        elif isinstance(cls, list):
            val = [self.dump_attr(cls[0], v, exclude_attributes) for v in item]
        else:
            val = item.dump(exclude_attributes=exclude_attributes)

        return val

    def dump(self, exclude_attributes: Optional[List[str]] = None) -> dict:
        _exclude_attributes = exclude_attributes or []
        info = {}
        for attr, cls in self.parameter.items():
            if attr in _exclude_attributes or attr in self.special_load_dump:
                continue

            item = getattr(self, attr, None)
            if item is None:
                continue

            info[attr] = self.dump_attr(cls, item, exclude_attributes)

        for attr, func in self.special_load_dump.items():
            item = getattr(self, attr, None)
            if item:
                if "dump" in func:
                    info[attr] = func["dump"](item, exclude_attributes=exclude_attributes)
                else:
                    cls = self.parameter[attr]
                    info[attr] = self.dump_attr(cls, item, exclude_attributes)

        return info

    def local_load_adjustments(self, **kwargs):
        pass

    def load_attr(
            self,
            cls: Any,
            item: Any,
            init_args: Optional[dict] = None,
            load_args: Optional[dict] = None,
    ) -> Any:
        if load_args:
            _kwargs = {"load_args": load_args}
        else:
            _kwargs = {}

        if init_args:
            _kwargs["init_args"] = init_args

        if cls in [None, 0, "", bool]:
            if cls == "" and item.startswith("BYTES:"):
                val = base64.b64decode(item[len("BYTES:"):].encode("utf-8"))
            else:
                val = item
        elif cls == b"":
            val = base64.b64decode(item[len("BYTES:"):].encode("utf-8"))
        elif cls == {}:
            val = {k: self.load_attr(type2cls(v), v, init_args, load_args) for k, v in item.items()}
        elif cls == []:
            val = [self.load_attr(type2cls(v), v, init_args, load_args) for v in item]
        elif cls == "DICT_TYPE":
            if list(item.keys()) == ["DICT_TYPE"]:
                _spec = item["DICT_TYPE"]
                val = importer(_spec["class"])(**_spec["kwargs"])
            else:
                val = item
        elif cls == object:
            val = importer(item)
        elif isinstance(cls, list):
            if isinstance(cls[0], str):
                _cls = importer(cls[0])
            else:
                _cls = cls[0]

            if issubclass(_cls, ImpExp) and init_args:
                _args = {k: v for k, v in init_args.items() if k in _cls.init_args}
            else:
                _args = {}

            val = [_cls(**_args).load(v, **_kwargs) for v in item]
        elif issubclass(cls, Message):
            _cls_name = list(item.keys())[0]
            _cls = importer(_cls_name)
            val = _cls().from_dict(item[_cls_name])
        else:
            if issubclass(cls, ImpExp) and init_args:
                _args = {k: v for k, v in init_args.items() if k in cls.init_args}
            else:
                _args = {}

            if item:
                val = cls(**_args).load(item, **_kwargs)
            else:
                val = cls(**_args)

        return val

    def load(self, item: dict, init_args: Optional[dict] = None, load_args: Optional[dict] = None):
        if load_args:
            _kwargs = {"load_args": load_args}
            _load_args = load_args
        else:
            _kwargs = {}
            _load_args = {}

        if init_args:
            for attr, val in init_args.items():
                if attr in self.init_args:
                    setattr(self, attr, val)

        _kwargs["init_args"] = init_args

        for attr, cls in self.parameter.items():
            if attr not in item or attr in self.special_load_dump:
                continue

            _cls_init_args = getattr(cls, "init_args", {})

            for param, target in {"upstream_get": "unit_get", "conf": "conf",
                                  "token_handler_args": "token_handler_args"}.items():
                target_val = getattr(self, target, None)
                if target_val:
                    if param in _cls_init_args and param not in _kwargs:
                        if _kwargs["init_args"] is None:
                            _kwargs["init_args"] = {param: target_val}
                        else:
                            _kwargs["init_args"][param] = target_val

            setattr(self, attr, self.load_attr(cls, item[attr], **_kwargs))

        for attr, func in self.special_load_dump.items():
            if attr in item:
                if "load" in func:
                    setattr(self, attr, func["load"](item[attr], **_kwargs))
                else:
                    cls = self.parameter[attr]
                    setattr(self, attr, self.load_attr(cls, item[attr], **_kwargs))

        self.local_load_adjustments(**_load_args)
        return self

    def flush(self):
        """
        Reset the content of the instance to its pristine state

        :return: A reference to the instance itself
        """
        for attr, cls in self.parameter.items():
            if cls is None:
                setattr(self, attr, None)
            elif cls == 0:
                setattr(self, attr, 0)
            elif cls is bool:
                setattr(self, attr, False)
            elif cls == "":
                setattr(self, attr, "")
            elif cls == []:
                setattr(self, attr, [])
            elif cls == {}:
                setattr(self, attr, {})
            else:
                setattr(self, attr, None)
        return self
