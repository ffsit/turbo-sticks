from __future__ import annotations

from collections.abc import Callable, Iterator
from enum import Enum, IntEnum
from typing import Any


class PydanticLaxEnum(Enum):
    """
    A version of Enum where Pydantic will accept the member names as values
    but also the member values and members themselves. By default it would
    only accept the individual values of the Enum.
    """

    @classmethod
    def __get_validators__(cls) -> Iterator[Callable[[Any], Any]]:
        yield cls.validate

    @classmethod
    def validate(cls, value: Any) -> Any:
        for item in cls:
            if value in (item.name, item.value, item):
                return item.value

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
