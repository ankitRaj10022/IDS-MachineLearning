from __future__ import annotations

import sys

from . import product_terminal


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0].lower() == "gui":
        from .product_gui import main as gui_main

        return gui_main(args[1:])
    return product_terminal.main(args)


if __name__ == "__main__":
    raise SystemExit(main())
