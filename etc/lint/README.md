# How to add a new lint

Add your lint to a python module:

```python
import click
from etc.lint import LintResult

def my_fun_lint(ctx: click.Context) -> LintResult:
    if mercury_is_in_retrograde():
        print("This lint will fail now.")
        return LintResult.FAILURE
    else:
        return LintResult.SUCCESS
```

And then add your lint to the list in `etc/lint/cmd.py`

