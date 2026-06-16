"""Entry point for ``python -m ssh_manager`` and the frozen engine binary.

The Go front-end (v2) invokes the engine as an executable; this module makes the
package directly runnable so the same code backs the console script, ``-m``, and
the PyInstaller freeze.
"""
from ssh_manager.cli import main

if __name__ == "__main__":
    main()
