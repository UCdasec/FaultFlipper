#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "qemu-plugin.h"

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static FILE *outf = NULL;
static uint64_t text_start = 0;
static uint64_t text_end   = 0;
static int code_range_ready = 0;

/* ---------- EXECUTION CALLBACK ---------- */

static void insn_exec_cb(unsigned int cpu_index, void *udata)
{
    (void)cpu_index;
    struct qemu_plugin_insn *insn = (struct qemu_plugin_insn *)udata;

    if (!code_range_ready) {
        return;
    }

    uint64_t pc = qemu_plugin_insn_vaddr(insn);

    if (pc < text_start || pc >= text_end) {
        return;
    }

    uint64_t offset = pc - text_start;

    if (outf) {
        fwrite(&offset, sizeof(offset), 1, outf);
    }
}

/* ---------- TB CALLBACK ---------- */

static void tb_trans_cb(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    (void)id;
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

/* ---------- VCPU INIT CALLBACK (FIXED SIGNATURE) ---------- */

static void vcpu_init_cb(qemu_plugin_id_t id, unsigned int cpu_index)
{
    (void)id;
    (void)cpu_index;

    text_start = qemu_plugin_start_code();
    text_end   = qemu_plugin_end_code();

    if (text_start == 0 || text_end <= text_start) {
        code_range_ready = 0;
        fprintf(stderr,
                "QEMU plugin: warning: start/end code not valid "
                "(start=0x%lx end=0x%lx)\n",
                (unsigned long)text_start, (unsigned long)text_end);
    } else {
        code_range_ready = 1;
        /* Optional debug:
        fprintf(stderr,
                "QEMU plugin: code range [0x%lx, 0x%lx)\n",
                (unsigned long)text_start, (unsigned long)text_end);
        */
    }
}

/* ---------- CLEANUP ---------- */

__attribute__((destructor))
static void plugin_cleanup(void)
{
    if (outf) {
        fclose(outf);
        outf = NULL;
    }
}

/* ---------- INSTALL ---------- */

QEMU_PLUGIN_EXPORT int
qemu_plugin_install(qemu_plugin_id_t id,
                    const qemu_info_t *info,
                    int argc, char **argv)
{
    (void)info;

    const char *fname = "insn_trace.bin";

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
        perror("qemu-plugin: fopen trace file");
        return 1;
    }

    qemu_plugin_register_vcpu_init_cb(id, vcpu_init_cb);
    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_trans_cb);

    return 0;
}

