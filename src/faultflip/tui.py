# shell.py

import sys
from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout

# Import the same 'app' from cli.py
import cli
from cli import console
from rich.console import Console

# console = Console()
from prompt_toolkit.output.color_depth import ColorDepth


from prompt_toolkit.output import create_output
from prompt_toolkit.patch_stdout import patch_stdout

import colorama

colorama.init()


def main():
    my_output = create_output()
    session = PromptSession(
        "(FancyShell) > ", output=my_output, color_depth=ColorDepth.TRUE_COLOR
    )
    # cli.app("--help")
    # with patch_stdout():
    while True:
        try:
            # Prompt the user
            user_input = session.prompt()

            if not user_input.strip():
                # If they hit enter on empty line, just prompt again
                continue

            # Check for exit keywords
            if user_input.strip().lower() in ["exit", "quit"]:
                print("Exiting shell. Goodbye!")
                break

            # Split user input into arguments
            cli_args = user_input.split()

            # Here is the magic: hand the arguments to your cyclopts app
            try:
                cli.app(cli_args)
            # except Exception as e:
            except:
                print("Here")
                continue

        except KeyboardInterrupt:
            # Handle Ctrl-C by ignoring or printing a message
            print("^C")
            continue
        except EOFError:
            # Handle Ctrl-D
            print("\nExiting shell. Goodbye!")
            break
        except Exception as e:
            print(e)
            print(f"Leaving ??")
            continue
    print("out")


if __name__ == "__main__":
    main()
