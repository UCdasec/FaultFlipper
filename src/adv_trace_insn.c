#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "qemu-plugin.h"

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static FILE *outf = NULL;

#define MAX_INSN_BYTES 32  // should be plenty

typedef struct InsnInfo {
    uint64_t pc;
    uint8_t size;
    uint8_t bytes[MAX_INSN_BYTES];
} InsnInfo;

// EXECUTION CALLBACK — called for each instruction
static void insn_exec_cb(unsigned int vcpu_idx, void *udata)
{
    (void)vcpu_idx;
    InsnInfo *info = (InsnInfo *)udata;
    if (!outf || !info) {
        return;
    }

    fprintf(outf, "PC: 0x%llx, Size: %u, Bytes:",
            (unsigned long long)info->pc,
            (unsigned int)info->size);

    for (uint8_t i = 0; i < info->size; i++) {
        fprintf(outf, " %02x", info->bytes[i]);
    }
    fputc('\n', outf);
}

// TB callback — register per-insn exec callbacks, caching bytes here
static void tb_trans_cb(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    (void)id;
    int n = qemu_plugin_tb_n_insns(tb);

    for (int i = 0; i < n; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);

        InsnInfo *info = (InsnInfo *)malloc(sizeof(InsnInfo));
        if (!info) {
            // If we fail to allocate, just skip this instruction.
            continue;
        }

        info->pc = qemu_plugin_insn_vaddr(insn);

        size_t sz = qemu_plugin_insn_size(insn);
        if (sz > MAX_INSN_BYTES) {
            sz = MAX_INSN_BYTES;
        }
        info->size = (uint8_t)sz;

        size_t got = qemu_plugin_insn_data(insn, info->bytes, sz);
        if (got < sz) {
            // Zero-fill the tail if we didn't get all bytes
            for (size_t j = got; j < sz; j++) {
                info->bytes[j] = 0;
            }
            info->size = (uint8_t)got;
        }

        qemu_plugin_register_vcpu_insn_exec_cb(
            insn,
            insn_exec_cb,
            QEMU_PLUGIN_CB_NO_REGS,
            info  // will be used by exec callback
        );
    }
}

// CLEANUP — we don't free InsnInfo; QEMU exits anyway
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

    const char *fname = "insn_trace.txt";  // default

    // Parse plugin args: input=<path>
    for (int i = 0; i < argc; i++) {
        const char *arg = argv[i];
        const char *eq = strchr(arg, '=');
        if (!eq) {
            continue;
        }

        size_t key_len = (size_t)(eq - arg);
        if (key_len == 5 && strncmp(arg, "input", 5) == 0) {
            fname = eq + 1;
        }
    }

    outf = fopen(fname, "w");
    if (!outf) {
        perror("fopen trace file");
        return 1;
    }

    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_trans_cb);
    return 0;
}

