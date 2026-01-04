#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "qemu-plugin.h"

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static FILE *outf = NULL;

// EXECUTION CALLBACK — called for each instruction
static void insn_exec_cb(unsigned int cpu, void *udata)
{
    struct qemu_plugin_insn *insn = udata;
    uint64_t pc = qemu_plugin_insn_vaddr(insn);  // Get the PC of the instruction
    if (outf) {
        fwrite(&pc, sizeof(pc), 1, outf);  // Write PC to the trace file
    }
}

// TRANSLATED BLOCK CALLBACK — called per translated block
static void tb_trans_cb(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    int n = qemu_plugin_tb_n_insns(tb);  // Number of instructions in this block

    // Loop through all the instructions in the translated block
    for (int i = 0; i < n; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);

        // Register the instruction execution callback for each instruction
        qemu_plugin_register_vcpu_insn_exec_cb(
            insn,               // instruction
            insn_exec_cb,       // callback function
            QEMU_PLUGIN_CB_NO_REGS,  // we don't need registers
            insn                // pass the instruction as userdata (used in exec callback)
        );
    }
}

// CLEANUP CALLBACK (called when process exits)
__attribute__((destructor))
static void plugin_cleanup(void)
{
    if (outf) {
        fclose(outf);  // Close the trace file
        outf = NULL;
    }
}

// PLUGIN INSTALL FUNCTION
QEMU_PLUGIN_EXPORT int
qemu_plugin_install(qemu_plugin_id_t id,
                    const qemu_info_t *info,
                    int argc, char **argv)
{
    (void)info;  // We don't use this for now

    const char *fname = "insn_trace.bin";  // Default trace file name
    //
    printf("Debug: Arguments passed to plugin:\n");
    for (int i = 0; i < argc; i++) {
        printf("argv[%d]: %s\n", i, argv[i]);
    }

    // Parse arguments passed by QEMU: look for file=<path>
    printf("Plugin install: argc: %d\n", argc);

    for (int i = 0; i < argc; i++) {
        const char *arg = argv[i];
        printf(" argv[%d] = '%s'\n", i, argv[i]);
        const char *eq = strchr(arg, '=');

        if (!eq) {
            continue;
        }

        size_t key_len = (size_t)(eq - arg);
        printf("Checking argv[%d]: %s\n", i, argv[i]);

        if (key_len == 5 && strncmp(arg, "input", 5) == 0) {
            printf("SETTING argv[%d]: %s\n", i, argv[i]);
            fname = eq + 1;  // everything after "file="
            printf("Debug: Received trace file path: %s\n", fname);  // Debug print
        }
    }

    // Open the file for writing (binary mode)
    printf("Opening trace file: %s\n", fname);
    outf = fopen(fname, "wb");
    if (!outf) {
        perror("fopen trace file");
        return 1;  // If fopen fails, return non-zero to indicate failure
    }

    // Register the translated block callback (per TB)
    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_trans_cb);

    return 0;  // Return 0 to indicate successful installation
}

