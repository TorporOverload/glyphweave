
import sys


def main() -> None:
    args = sys.argv[1:]
    if not args:
        from app.ui.gui.glyphweave_ui import gui_main
        entry = gui_main
    elif args[0] == "cli":
        from app.ui.cli.app import run_cli
        entry = run_cli
    else:
        print("Invalid argument. Use 'cli' for CLI mode.")
        sys.exit(1)
    raise SystemExit(entry())


if __name__ == "__main__":
    main()