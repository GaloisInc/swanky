from .rust import _contains_deny_missing_docs


def test_contains_deny_missing_docs() -> None:
    yes = [
        b"#![deny(missing_docs)]",
        b"#![deny(foo, missing_docs)] fn blarg() {}",
        b"#![deny(foo)] #![deny(missing_docs)]",
    ]
    no = [b"let x = 12;", b"// #![deny(missing_docs)]"]
    for x in yes:
        assert _contains_deny_missing_docs(x)
    for x in no:
        assert not _contains_deny_missing_docs(x)
