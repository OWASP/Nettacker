push   $0x0f
pop    %eax
{0}
{1}
mov    %esp,%ebx
int    $0x80
mov    $0x01,%al
mov    $0x01,%bl
int    $0x80