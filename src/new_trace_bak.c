#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "qemu-plugin.h"

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static FILE *outf = NULL;
static uint64_t text_start = 0;
static uint64_t text_end   = 0;

// EXECUTION CALLBACK — called for each instruction
static void insn_exec_cb(unsigned int cpu, void *udata)
{
    struct qemu_plugin_insn *insn = udata;
    uint64_t pc = qemu_plugin_insn_vaddr(insn);

    // Only keep instructions in the main code range
    if (pc < text_start || pc >= text_end) {
        return;
    }

    // Normalize out ASLR: store offset within code
    uint64_t offset = pc - text_start;

    if (outf) {
        fwrite(&offset, sizeof(offset), 1, outf);
    }
}

// TRANSLATED BLOCK CALLBACK — called per TB
static void tb_trans_cb(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    int n = qemu_plugin_tb_n_insns(tb);

    for (int i = 0; i < n; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);

        qemu_plugin_register_vcpu_insn_exec_cb(
            insn,
            insn_exec_cb,
            QEMU_PLUGIN_CB_NO_REGS,
            insn
        );
    }
}

// CLEANUP
__attribute__((destructor))
static void plugin_cleanup(void)
{
    if (outf) {
        fclose(outf);
        outf = NULL;
    }
}

// INSTALL
QEMU_PLUGIN_EXPORT int
qemu_plugin_install(qemu_plugin_id_t id,
                    const qemu_info_t *info,
                    int argc, char **argv)
{
    (void)info;

    const char *fname = "insn_trace.bin";

    // Parse args: input=<path>
    for (int i = 0; i < argc; i++) {
        const char *arg = argv[i];
        const char *eq = strchr(arg, '=');
        if (!eq) continue;

        size_t key_len = (size_t)(eq - arg);
        if (key_len == 5 && strncmp(arg, "input", 5) == 0) {
            fname = eq + 1;
        }
    }

    outf = fopen(fname, "wb");
    if (!outf) {
        perror("fopen trace file");
        return 1;
    }

    // Record code range for the main binary (handles PIE vs non-PIE)
    text_start = qemu_plugin_start_code();
    text_end   = qemu_plugin_end_code();

    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_trans_cb);
    return 0;
}

