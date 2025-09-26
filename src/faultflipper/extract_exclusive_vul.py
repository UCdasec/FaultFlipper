import re
import os
import shutil
tasks = ["pass_check", 
         "pass_double_check", 
         "fib", 
         "fib_loop_check"
        ]

all_comb_2_nop_md_file = {
    "pass_check":           "experiments/iter_2_nop_comb_password/",
    "pass_double_check":    "experiments/iter_2_nop_comb_password_DOUBLE_check/",
    "fib":                  "experiments/iter_2_nop_comb_fib/",
    "fib_loop_check":       "experiments/iter_2_nop_comb_fib_LOOPCHECK/"
}
iter_2_nop_md_file= {
    "pass_check":           "experiments/1_nop_comb_password/",
    "pass_double_check":    "experiments/1_nop_comb_password_DOUBLE_check/",
    "fib":                  "experiments/1_nop_comb_fib/",
    "fib_loop_check":       "experiments/1_nop_comb__fib_LOOPCHECK/"
}

def extract_filename(text):
    section_pattern = (
        r"## List of Event Upset Mutations:\n\n(.*?)(?=^#### Original Program vs Program\s+\d+ .+?\.o(?:_0x[0-9a-f]+)+\s+diassemebly$)"
    )

    match = re.search(section_pattern, text, re.DOTALL | re.MULTILINE)
    if match:
        section_text = match.group(1)
        filename_pattern = r"\b\S+\.o(?:_0x[0-9a-f]+)+\b"
        filenames = re.findall(filename_pattern, section_text)
        filenames = list(set(filenames))
        address_pairs = []
        for name in filenames:
            name = name.split(".o")[1].split("_")[1:]
            address_pairs.append(name)
        return address_pairs
    else:
        print("NOT FOUND THE FILE")
        return []

if "__main__" == __name__:
    for task in tasks:
        with open(all_comb_2_nop_md_file[task] + "report.md", "r", encoding="utf-8") as f:
            read_md_all_comb = f.read()
            all_comb_addr = extract_filename(read_md_all_comb)
            

        with open( iter_2_nop_md_file[task]+ "report.md", "r", encoding="utf-8") as f:
            read_md_iter = f.read()
            iter_addr = extract_filename(read_md_iter)
        
        print(f"[{task}] Before filtering: ",len(all_comb_addr))

        all_comb_addr = [
            all_comb for all_comb in all_comb_addr
            if not any(iter[0] in all_comb for iter in iter_addr)
        ]
        print(f"[{task}] After filtering: ",len(all_comb_addr))
        

        src_folder = all_comb_2_nop_md_file[task] + "mutated_bins/"
        dest_folder = all_comb_2_nop_md_file[task] + "vulnerable_bins/"
        os.makedirs(dest_folder, exist_ok=True)

        all_files = os.listdir(src_folder)
        count = 0
        for addr in all_comb_addr:
            addr = "_".join(addr)
            for filename in all_files:
                if addr in filename:
                    count += 1
                    src_path = os.path.join(src_folder, filename)
                    dst_path = os.path.join(dest_folder, filename)
                    # shutil.copy2(src_path, dst_path)
        print(f"Already copied: {count} vulnerable files to {dest_folder}")
        print("================================================")