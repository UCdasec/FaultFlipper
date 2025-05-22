
import subprocess
from cyclopts import App, Parameter
from rich.table import Table
from rich.console import Console
from pathlib import Path

console = Console()
app = App()



@app.command()
def test_bin(bin: Path, is_arm32: bool, image_dir: Path):
    """
    Test the binary on the input images.

    Binary must be generated as described in the readme
    """

    if not bin.exists() or not image_dir.is_dir():
        raise Exception("Make sure the binary / image dir exist")


    if is_arm32:
        run_cmd = f"qemu-arm-static -L /usr/arm-linux-gnueabi {bin.absolute()}"
    else:
        run_cmd = f"{bin.absolute()}"

    correct = 0
    incorrect = 0


    # Iterate over the images 
    for inp in image_dir.glob('*'):
        name, _, lbl = inp.name.split("_")
        lbl = lbl.split('.')[0]

        # Run the binary
        args = run_cmd.split(' ')
        args.append(str(inp.absolute()))
        out = subprocess.check_output(args)

        if lbl in out.decode():
            correct +=1 
        else:
            incorrect+=1

    print(f"Correct: {correct}")
    print(f"Incorrect: {incorrect}")
    print(f"Accuracy: {correct/(correct+incorrect)}")

    return

if __name__ == "__main__":
    app()
