
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

    code = request.POST.get("code", "")
    output = None
    error = None
    print(f"code {code}")

    if request.method == "POST" and code:
        try:
            print('executing ')
            # VULNERABLE LINE: exec() on raw, untrusted user input.
            local_vars = {}
            exec(code, {}, local_vars)          # <-- DANGEROUS
            print(f"Local vars after exec: {local_vars}")
        except Exception as exc:  # noqa: BLE001 - demo only
            error = f"{type(exc).__name__}: {exc}"

    return render(
        request,
        "vulnapp/runner.html",
        {"code": code, "output": output, "error": error},
    )
