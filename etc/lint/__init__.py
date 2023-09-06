import enum


@enum.unique
class LintResult(enum.Enum):
    """
    Did a lint succeed or not?

    A lint normally fails if --check was passed, and formatting is needed.
    """

    SUCCESS = enum.auto()
    FAILURE = enum.auto()
