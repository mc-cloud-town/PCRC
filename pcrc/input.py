from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Generic, TypeVar

if TYPE_CHECKING:
    from pcrc.pcrc_client import PcrcClient

_CLIENT = TypeVar("_CLIENT", bound="PcrcClient")


class InputManager(ABC, Generic[_CLIENT]):
    def __init__(self, client: _CLIENT) -> None:
        self.client: _CLIENT = client

    @abstractmethod
    def input(self, message: str) -> str:
        raise NotImplementedError()


class StdinInputManager(InputManager):
    def input(self, message: str) -> str:
        return input(message)
