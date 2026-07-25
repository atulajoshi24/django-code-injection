"""
Teaching demo: Code Injection (CWE-94) via eval()/exec().

This module intentionally contains vulnerable code so students can see,
exploit, and then fix a real code-injection bug. Each view is documented
with what makes it dangerous and, where relevant, a fixed counterpart.

SAFETY: Only run this on your own machine, offline, for a classroom demo.
eval()/exec() on user input allow full arbitrary code execution on the
server (read/write files, spawn processes, exfiltrate secrets, etc.) -
never deploy this code, even temporarily, on a host reachable by anyone
else.
"""
import ast
import io
import contextlib

from django.shortcuts import render


def home(request):
    return render(request, "vulnapp/home.html")


# ---------------------------------------------------------------------------
# 1) VULNERABLE: eval() used to implement a "calculator"
# ---------------------------------------------------------------------------
def vulnerable_calculator(request):
    """
    Takes a math expression from the user and evaluates it with eval().

    Why it's vulnerable:
    eval() doesn't just do arithmetic - it runs *any* Python expression,
    including attribute access and function calls. Because Python lets you
    reach almost any object from builtins, a user-supplied string like:

        __import__('os').system('whoami')

    or, if __builtins__ has been stripped naively:

        ().__class__.__base__.__subclasses__()

    can be used to escape the "calculator" sandbox entirely and run
    arbitrary commands on the server.

    Try these in the input box:
        2 + 2
        __import__('os').getcwd()
        __import__('os').popen('whoami').read()
        [x for x in ().__class__.__base__.__subclasses__() if 'Popen' in str(x)]
    """
    expression = request.GET.get("expression", "")
    result = None
    error = None

    if expression:
        try:
            # VULNERABLE LINE: eval() on raw, untrusted user input.
            result = eval(expression)
        except Exception as exc:  # noqa: BLE001 - demo only, want to show any failure
            error = f"{type(exc).__name__}: {exc}"

    return render(
        request,
        "vulnapp/calculator.html",
        {"expression": expression, "result": result, "error": error},
    )


# ---------------------------------------------------------------------------
# 2) SAFE: the same calculator feature, fixed
# ---------------------------------------------------------------------------
# Only these AST node types are permitted - no Name, Call, Attribute, etc.
# So no function calls, no attribute access, no variables: just numbers
# and arithmetic operators. This is what makes it safe, unlike eval().
_ALLOWED_NODES = (
    ast.Expression,
    ast.BinOp,
    ast.UnaryOp,
    ast.Constant,
    ast.Add,
    ast.Sub,
    ast.Mult,
    ast.Div,
    ast.FloorDiv,
    ast.Mod,
    ast.Pow,
    ast.USub,
    ast.UAdd,
)


def _safe_eval_arithmetic(expression: str) -> float:
    """
    Evaluate a *pure arithmetic* expression safely.

    Instead of trusting the interpreter to only do arithmetic (eval doesn't
    make that promise), we parse the expression into an AST ourselves and
    reject anything that isn't a number or a basic math operator. There is
    no code path here that can call a function, import a module, or touch
    an attribute - so there is nothing for an attacker to escape into.
    """
    tree = ast.parse(expression, mode="eval")

    for node in ast.walk(tree):
        if not isinstance(node, _ALLOWED_NODES):
            raise ValueError(f"Disallowed expression element: {type(node).__name__}")
        if isinstance(node, ast.Constant) and not isinstance(node.value, (int, float)):
            raise ValueError("Only numeric constants are allowed")

    # compile() + eval() here is safe ONLY because we've already proven,
    # via the AST walk above, that the tree cannot contain calls, names,
    # attribute access, imports, etc.
    code = compile(tree, "<safe_expression>", "eval")
    return eval(code, {"__builtins__": {}}, {})


def safe_calculator(request):
    expression = request.GET.get("expression", "")
    result = None
    error = None

    if expression:
        try:
            result = _safe_eval_arithmetic(expression)
        except Exception as exc:  # noqa: BLE001 - demo only
            error = f"{type(exc).__name__}: {exc}"

    return render(
        request,
        "vulnapp/safe_calculator.html",
        {"expression": expression, "result": result, "error": error},
    )


# ---------------------------------------------------------------------------
# 3) VULNERABLE: exec() used to run a user-supplied "script"
# ---------------------------------------------------------------------------
def vulnerable_runner(request):
    """
    Runs arbitrary user-supplied Python statements with exec().

    Why it's vulnerable:
    exec() runs full statements, not just expressions - imports, file I/O,
    process spawning, infinite loops, everything. There is effectively no
    safe way to sandbox exec()/eval() against a determined attacker from
    pure Python; the only real fix is to not run untrusted code at all, or
    to isolate it in a properly sandboxed environment (separate process,
    container, gVisor/Firecracker, seccomp, etc.) with no access to
    secrets or the network.

    Try this in the textarea:
        import os
        print(os.getcwd())
        print(os.listdir('.'))
    """
    code = request.POST.get("code", "")
    output = None
    error = None

    if request.method == "POST" and code:
        buffer = io.StringIO()
        try:
            with contextlib.redirect_stdout(buffer):
                # VULNERABLE LINE: exec() on raw, untrusted user input.
                exec(code)
            output = buffer.getvalue()
        except Exception as exc:  # noqa: BLE001 - demo only
            error = f"{type(exc).__name__}: {exc}"

    return render(
        request,
        "vulnapp/runner.html",
        {"code": code, "output": output, "error": error},
    )
