from __future__ import annotations

from collections.abc import Callable
from enum import Enum, IntEnum
from pydantic_core import core_schema
from typing import Any


class PydanticLaxEnum(Enum):
    """
    A version of Enum where Pydantic will accept the member names as values
    but also the member values and members themselves. By default it would
    only accept the individual values of the Enum.
    """

    @classmethod
    def __get_pydantic_core_schema__(
        cls,
        _source_type: Any,
        _handler: Callable[[Any], core_schema.CoreSchema]
    ) -> core_schema.CoreSchema:

        value_schema: core_schema.CoreSchema
        base_schema: core_schema.CoreSchema
        if issubclass(cls, IntEnum):
            value_schema = core_schema.int_schema()
            base_schema = core_schema.union_schema([
                value_schema,
                core_schema.str_schema()
            ])
        else:
            # make sure all the values are strings
            assert all(isinstance(m.value, str) for m in cls)
            value_schema = core_schema.str_schema()
            base_schema = value_schema

        lax_schema = core_schema.chain_schema([
            base_schema,
            core_schema.no_info_plain_validator_function(cls.validate)
        ])
        strict_schema = core_schema.json_or_python_schema(
            json_schema=core_schema.no_info_after_validator_function(
                cls.validate,
                value_schema
            ),
            python_schema=core_schema.is_instance_schema(cls),
            serialization=core_schema.plain_serializer_function_ser_schema(
                lambda self: self.name
            )
        )
        return core_schema.lax_or_strict_schema(
            lax_schema=lax_schema,
            strict_schema=strict_schema
        )

    @classmethod
    def validate(cls, value: Any) -> Any:
        for item in cls:
            if value in (item.name, item.value, item):
                return item

        raise ValueError(
            f'Invalid value {value}. Allowed={list(cls.__members__.keys())}'
        )


class ACL(PydanticLaxEnum, IntEnum):
    guest = 0
    patron = 10
    turbo = 20
    helper = 30
    moderator = 40
    crew = 50
    admin = 60
