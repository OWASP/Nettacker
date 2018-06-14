{0}
mov    %esp,%ebx
xor    %eax,%eax
push   %eax
mov    %esp,%edx
push   %ebx
mov    %esp,%ecx
push   %edx
push   %ecx
push   %ebx
mov    $0x3b,%al
push   $0x2a
int    $0x80
mov    $0x1,%al
mov    $0x1,%bl
int    $0x80