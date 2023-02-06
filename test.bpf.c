// +build ignore

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("lsm/bprm_check_security")
int BPF_PROG(bprm_stuff, struct linux_binprm *bprm, int ret) {
  bpf_printk("exec of %s", bprm->filename);
  return ret;
}
