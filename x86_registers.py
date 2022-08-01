"""
Contains lists of registers to be used by other functions
"""

X86_64_REGISTERS = ['rax',
                    'rbx',
                    'rcx',
                    'rdx',
                    'rsi',
                    'rdi',
                    'rbp',
                    'rsp',
                    'r8',
                    'r9',
                    'r10',
                    'r11',
                    'r12',
                    'r13',
                    'r14',
                    'r15']

X86_32_REGISTERS = ['eax',
                    'ebx',
                    'ecx',
                    'edx',
                    'esp',
                    'ebp',
                    'esi',
                    'edi']


def is_register(operand):
    """
    Checks if a given operand is a x86-64 register
    """
    return operand in X86_64_REGISTERS or operand in X86_32_REGISTERS

def is_32bit(register):
    """
    Checks if a register is 32 bit
    """
    return register in X86_32_REGISTERS

def convert_32_to_64(register_32):
    """
    Converts a 32 bit register to an equivalent 64 bit register
    """
    for register_64 in X86_64_REGISTERS[:7]:
        if register_32[1:] == register_64[1:]:
            return register_64
    return register_32
