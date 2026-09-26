# bpfret.py TYPE RET PIN -- load a two-instruction BPF program of TYPE
# (xdp or tc) that always returns RET, and pin it at PIN. Enough to stand
# in for a dropping XDP / tc program without a compiler.
import ctypes, os, struct, sys
libc = ctypes.CDLL(None, use_errno=True)
SYS_bpf = {"x86_64": 321, "aarch64": 280}[os.uname().machine]
BPF_PROG_LOAD, BPF_OBJ_PIN = 5, 6
ptype = {"xdp": 6, "tc": 3}[sys.argv[1]]  # BPF_PROG_TYPE_XDP / SCHED_CLS
ret = int(sys.argv[2])
insns = struct.pack("<BBhi", 0xb7, 0, 0, ret) + struct.pack("<BBhi", 0x95, 0, 0, 0)
buf, lic = ctypes.create_string_buffer(insns), ctypes.create_string_buffer(b"GPL")
attr = ctypes.create_string_buffer(128)
struct.pack_into("<IIQQ", attr, 0, ptype, 2, ctypes.addressof(buf), ctypes.addressof(lic))
fd = libc.syscall(SYS_bpf, BPF_PROG_LOAD, attr, 128)
if fd < 0:
    sys.exit("prog load: " + os.strerror(ctypes.get_errno()))
path = ctypes.create_string_buffer(sys.argv[3].encode())
attr = ctypes.create_string_buffer(128)
struct.pack_into("<QI", attr, 0, ctypes.addressof(path), fd)
if libc.syscall(SYS_bpf, BPF_OBJ_PIN, attr, 128) < 0:
    sys.exit("pin: " + os.strerror(ctypes.get_errno()))
