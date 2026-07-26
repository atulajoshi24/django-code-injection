
import ast
import io
import contextlib
import numexpr as ne
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


def _safe_eval_arithmetic(expression: str) -> float:
    print(f'_safe_eval_arithmetic {expression}')
    result = ne.evaluate(expression)
    return result

def safe_calculator(request):
    expression = request.GET.get("expression", "")
    result = None
    error = None
    print(f'expression {type(expression)}')

    if expression:
        try:
            result = _safe_eval_arithmetic(expression)
        except Exception as exc:  # noqa: BLE001 - demo only
            print(f'error {exc}')
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
