import re
from pathlib import Path
import subprocess
import pandas as pd


def df_to_obsidian(df:pd.DataFrame):
    """
    Generate the obsidian Mathjax for the dataframe
    """

    # Generate the LaTeX table with pandas
    latex_str = df.to_latex(index=False)
    
    # Remove formatting lines that MathJax doesn't need
    latex_str = re.sub(r"\\(toprule|midrule|bottomrule)[^\n]*\n", "", latex_str)
    
    
    # Replace the 'tabular' environment with 'array'
    latex_str = latex_str.replace("tabular", "array")
    
    # Optionally, remove the column format specifiers (e.g., {lrr})
    latex_str = re.sub(r"\{[lcr]+\}", "", latex_str)
    
    # Wrap in display math delimiters so that MathJax renders it properly in Obsidian
    latex_str = "$$\n" + latex_str + "\n$$"
    
    
    latex_str = latex_str.replace(r"\\",r"\\ \hline")
    col_str = "|c"*len(df.columns)+"|}"
    latex_str = latex_str.replace(r"\begin{array}",r"\begin{array}{"+col_str)

    return latex_str



def list_tuple_table(column_names:list[str], data:list[tuple])->str:
    """
    Make a table from a list of tuples
    """

    # Top
    ret = "$$\n"
    col_str = "|c"*len(column_names)+"|}"
    ret += r"\begin{array}{" + col_str + "\n"
    ret += r"\hline" 
    ret += "\n" 
    ret += " & ".join(column_names) + r"\\ \hline" + "\n"

    # Add all the lines
    for (k, v) in data:
        ret = ret + r"\text{" + k.replace("_"," ") + "} & " + f"{v} " + r"\\ \hline" + "\n"

    ret += r"\end{array}"
    ret += "\n"
    ret += "$$\n"

    return ret


def generate_pdf_report(inp:Path, out:Path):
    """
    genrate the report pdf
    """
    cmd = f"pandoc {inp} --pdf-engine=xelatex -V geometry:top=0.5in,left=0.125in,right=0.5in,bottom=0.5in -o {out} -V fontsize=8pt".split(" ")
    subprocess.run(cmd)
    return
