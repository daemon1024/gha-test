// +build ignore

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

typedef struct {
  u8 comm[80];
} event;
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("lsm/bprm_check_security")
int BPF_PROG(bprm_stuff, struct linux_binprm *bprm, int ret) {
  //   bpf_printk("exec of %s", bprm->filename);

  event *fn;

  fn = bpf_ringbuf_reserve(&events, sizeof(event), 0);
  if (!fn) {
    return 0;
  }

  bpf_probe_read_str(&fn->comm, 80, (void *)bprm->filename);

  bpf_ringbuf_submit(fn, 0);

  return ret;
}
