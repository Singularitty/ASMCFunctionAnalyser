# System modules
import subprocess
import re
import json

# User modules
import x86_registers

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[31m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class Disassembler:
    """
    This object contains procedures to disassemble the provided binary file

    Args:
        fname (str): Name of the file to be disassembled

    Requires:
        fname needs to represent a valid file

    Parameters:
        fname (str): Name of the disassembled file
        code (list[str]): Raw output of the objdump disassembly
    """

    def __init__(self, fname):
        self.fname = fname
        self.code = None
        self.__disas_objdump()

    def __disas_objdump(self):
        """
        Uses objdump to disassemble the .text section of the provided file
        """
        proc = subprocess.Popen(['objdump', '-M', 'intel', '-dj', '.text', self.fname], stdout=subprocess.PIPE)
        # Read from stdout, convert from binary format to str, split the str in lines and save it in a list
        self.code = proc.stdout.read().decode().splitlines()

    def display_disassembled_code(self):
        for line in self.code:
            print(line)


class Instruction:
    """
    Objects of this class represent a disassembled instruction

    Args:
        line (str): Disassembled line to be parsed

    Parameters:
        mnemoic (str): x86 Instruction
        addr (str): Hex address of instruction
        hex (str): Hexadecimal representation of instruction
        opr_str (str): Operands (can be more than 1) in a string, use split(',') to get each one
        relocation_addr (str): Not sure if this is the relocation address of the resolved names
        resolved_name (str): Resolved name by the disassembler (e.g: gets@plt)
    """

    def __init__(self, line):
        self.line = line
        self.mnemonic = None
        self.addr = None
        self.hex = None
        self.opr_str = None
        self.relocation_addr = None
        self.resolved_name = None
        self.__parse_instructions()

    def __str__(self):
        return self.line

    def __repr__(self):
        string = "[{mnemonic : " + self.mnemonic + "}, {addr : " + self.addr + "}, {hex : " + self.hex + \
                 "}, {opr_str : " + self.opr_str + "}, {resolved_name : " + str(self.resolved_name) + "}]"
        return string

    def __eq__(self, other):
        return isinstance(other, Instruction) and self.hex == other.hex

    def __parse_instructions(self):
        """
        Is called by the constructor to parse the given line of disassembled code.
        Uses a regex to divide the line in groups and saves each group to its respective parameter in the object
        """
        instruction_re = r'^\s*(0?[xX]?[\da-fA-F]{4}):\s*(([\da-fA-F]{2} ?)*)\s*([a-zA-Z\d]*)\s*(\w*,?([a-zA-Z\[\]\+\d-]* ?)*)\s*#?\s?([\da-fA-F]{4})?\s*\<?([a-zA-Z\_\@\+\d]*)\>?'
        matches = re.match(instruction_re, self.line)
        if matches:
            self.mnemonic = matches.group(4)
            self.addr = matches.group(1)
            self.hex = matches.group(2)
            self.opr_str = matches.group(5)
            self.relocation_addr = matches.group(7) if matches.group(7) else None
            self.resolved_name = matches.group(8) if matches.group(8) else None

    def interpret_instruction(self):
        """
        Tries to interpret an instruction returning the value it would
        give to the first operand, if it does an operation of that nature.
        Does not interpret instructions like calls or jumps, and returns
        None if it cannot interpret the instruction.

        Returns:
            (target (str), value (str): Interpreted result of the instruction
        """
        match self.mnemonic:
            case 'mov':
                return self.return_operands()
            case 'lea':
                addr_re = r'[(.+)]'
                ops = self.return_operands()
                matches = re.match(addr_re, ops[1])
                if matches:
                    return ops[0], matches.group(1)
                else:
                    return ops
            case _:
                return None, None


    def return_operands(self):
        """
        Parses the opr_str parameter of this instruction and returns the found operands in a
        list, in order of their appearance.

        E.g.:
            mov rax, rdx -> ['rax', 'rdx']

        Returns:
            list[str]: List of operands found in order of their appearance
        """
        return [op.strip() for op in self.opr_str.split(',')]

    def compare_addr(self, other):
        """
        Checks if two instructions have the same address
        """
        return isinstance(other, Instruction) and self.addr == other.addr

    def compare_mnemonic(self, other):
        """
        Checks if two instructions have the same mnemonic
        """
        return isinstance(other, Instruction) and self.mnemonic == other.mnemonic

    def __test(self):
        print(self.line)
        print(self.mnemonic)
        print(self.addr)
        print(self.hex)
        print(self.opr_str)
        print(self.relocation_addr)
        print(self.resolved_name)


class Parser:
    """
    This object contains the contents of the .text section of a binary elf file and methods to parse these contents.

    Args:
        disassembled_binary_code list[str]: .text section disassembly output from objdump

    Parameters:
        code list[str]: Disassembled lines from the .text section of an ELF binary file
        function (dict): Potential found functions (key = function label, content = lines belonging to that label)
        calls (dict): Addresses of found calls and their resolved names
    """

    def __init__(self, disassembled_binary_code):
        self.code = disassembled_binary_code
        self.instructions = []
        self.__parse_instructions()
        self.functions = {}
        self.__parse_functions()
        self.calls = {}
        self.__parse_calls()

    def __parse_instructions(self):
        """
        Converts each line of disassembled code into Instruction objects
        """
        for line in self.code:
            self.instructions.append(Instruction(line))

    def __parse_functions(self):
        """
        Parse the binary elf file in an attempt to identify and separate all the functions
        in the disassembled code.
        Note: Not all entries are actual C functions, but those will appear in this list.
        """

        function_re = r'(0?[xX]?[0-9a-fA-F]{8,16}) \<(\S+)\>:'
        in_function = False

        for line in self.code:
            matches = re.search(function_re, line)
            if matches:
                current_function = matches.group(2)
                self.functions[current_function] = []
                in_function = True
            elif in_function and line != "\n":
                self.functions[current_function].append(Instruction(line))
            if line == "\n":
                in_function = False

    def __parse_calls(self):
        """
        Parse the binary elf file in an attempt to identify and parse all the function calls
        Found calls are saved in a dict object, where the resolved name of the called function is used as
        a key.
        Note: If a call has no resolved name, it will be identified by its call address
        """

        call_re = r'\s*(0?[xX]?[\da-fA-F]{4}):\s+(([\da-fA-F]{2} ?)*)\s*call\s*(0?[xX]?[\da-fA-F]{4})\s*\<?([a-zA-Z\_\@\+\d]*)?\>?'

        for line in self.code:
            matches = re.search(call_re, line)
            if matches:
                if matches.group(5):
                    self.calls[matches.group(1)] = {'resolved_name': matches.group(5),
                                                    'call_addr': matches.group(4),
                                                    'hex': matches.group(2)}

    def __determine_instruction_function(self, addr):
        """
        Determines which function the given address of an instruction belongs to.
        """
        key_instruction = self.return_instruction_at(addr)
        for f_name, f_instructions in self.functions.items():
            for inst in f_instructions:
                if inst == key_instruction:
                    return f_name

    def get_instruction_range(self, start_addr, function_name=None, backwards=False):
        """
        Determines and returns a list of instructions starting at a given address and ending at the
        end or start of the specified function, depending on the value of backwards flag.

        Returns:
            list[Instruction]: List of instructions starting at the given address
        """
        starting_instruction = self.return_instruction_at(start_addr)
        if function_name is None:
            function = self.functions[self.__determine_instruction_function(start_addr)]
        else:
            function = self.functions[function_name]
        for indice, instruction in enumerate(function):
            if instruction == starting_instruction:
                if backwards:
                    sequence = function[:indice + 1]
                    sequence.reverse()
                    return sequence
                else:
                    sequence = function[indice:]
                    return sequence

    def return_instruction_at(self, addr: str):
        """
        Returns the instruction at the given address

        Requires:
            addr must be in hexadecimal form, but must not start with 0x
            E.g: addr = 12a4, 111f, ba23

        Returns:
            Instruction (object): Instruction at the given address
        """
        for i in self.instructions:
            if i.addr == addr:
                return i

    def display_functions(self):
        for (function_name, instructions) in self.functions.items():
            print(function_name + ":")
            for instruction in instructions:
                print(instruction)

    def display_calls(self):
        for (call_addr, call_content) in self.calls.items():
            print(f"{call_addr} : {call_content}")


class Analyser:
    """
    This object contains methods to analyse a disassembled function in order to determine if any C family functions
    are present and if they are properly parametrized.
    For this purpose ir records the contents of registers and the function stack while it analysis the code.

    Parameters:
        parser (Parser): BinaryParser object containing the .text section of the elf file and all functionality
                               related to parsing and iterating through instructions.
        stack (list): List representing the stack of the function
        registers (dict): Maps each register to a value which can be changed and read anytime
        param_order (list): Contains the order and names of the registers used to pass arguments to functions
    """

    def __init__(self, parser: Parser):
        self.parser = parser
        self.stack = []
        self.registers = {'rax': None,
                          'rbx': None,
                          'rcx': None,
                          'rdx': None,
                          'rsi': None,
                          'rdi': None,
                          'rbp': None,
                          'rsp': None,
                          'r8': None,
                          'r9': None,
                          'r10': None,
                          'r11': None,
                          'r12': None,
                          'r13': None,
                          'r14': None,
                          'r15': None}
        self.param_order = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
        self.found_c_function_calls = {}
        self.c_functions_database = None
        self.__import_function_data_json()
        self.__c_family_detector()

    def __import_function_data_json(self):
        with open("c_functions.json", 'r') as infile:
            self.c_functions_database = json.loads(infile.read())

    def __c_family_detector(self):
        """
        Iterates through all the identified calls by the parser and tries to identify and record which ones call
        a C-family function present in the program database. It then saves the address of that call and the corresponding
        c function name.
        """
        func_name_re = r'\W*([a-zA-Z0-9]+)\W*'
        for call_addr in self.parser.calls.keys():
            matches = re.match(func_name_re, self.parser.calls[call_addr]['resolved_name'])
            if matches:
                if matches.group(1) in self.c_functions_database:
                    self.found_c_function_calls[call_addr] = matches.group(1)

    def __warn_unsafe_function(self):
        """
        Iterates through the identified C-family functions and prints a warning message if it finds any function
        that is unsafe.
        """
        for (f_call_addr, f_call_name) in self.found_c_function_calls.items():
            if self.c_functions_database[f_call_name]['safe'] == 'no':
                print(f'Warning: unsafe function \'{f_call_name}\' is called at address 0x{f_call_addr}')

    def __determine_f_register_values(self, f_call_addr):
        """
        Tries to determine the parameters of the callee by iterating backwards from the call until
        the start of the current function. It determines the value of registers used in the System V
        call convention. It does not attempt to determine parameters stored in the stack.

        Returns:
            list[str]: List of System V convention registers which have an assigned value
        """
        instruction_range = self.parser.get_instruction_range(f_call_addr, backwards=True)
        for inst in instruction_range:
            # Get the operands of the current instruction
            ops = inst.return_operands()
            # Check if the target operand is a register
            if x86_registers.is_register(ops[0]):
                # Interpret the instruction in order to determine the value of register
                register, value = inst.interpret_instruction()
                # Check if the register is 32 bit, if so convert it to 64
                if x86_registers.is_32bit(register):
                    register = x86_registers.convert_32_to_64(register)
                # If a value is given to the register, record it
                if value is not None:
                    if self.registers[register] is None or x86_registers.is_register(self.registers[register]):
                        self.registers[register] = value
                    # Now check if any of the registers point to another register
                    for reg, val in self.registers.items():
                        # if a register points to another register, assign the other registers value
                        # to this register. E.g.: rdx = rax, but rax = 0xf, then rdx = 0xf
                        if val == register:
                            self.registers[reg] = value

    def __determine_buffer_size(self, register):
        """
        Extracts the offset from a register value of the type [rbp-0x], and converts it to decimal

        Returns:
            int: Size of the buffer specified by the offset from rbp in the given register, if it can't determine the
                 buffer size or if the value of the register does not conform to the specified format it returns 0
        """
        register_value = self.registers[register]
        hex_re = r'.*(0[xX][0-9a-fA-F]+).*'
        matches = re.match(hex_re, register_value)
        if matches:
            hex_value = matches.group(1)
            buffer_size = int(hex_value, 16)
            return buffer_size
        else:
            return 0

    def __verify_argument_validity(self, f_call_addr):
        """
        Tries to determine if the detected parameters of a function are valid and safe.
        """
        f_name = self.found_c_function_calls[f_call_addr]
        conditions = self.c_functions_database[f_name]['condition']
        vulnerable = False
        if conditions[0] != "None":
            cond_re = r'(\d) ([<>=]{1,2}) (\d)'
            for cond in conditions:
                matches = re.match(cond_re, cond)
                ind1, ind2 = int(matches.group(1)), int(matches.group(3))
                reg1 = self.param_order[ind1]
                reg2 = self.param_order[ind2]
                val1 = self.__determine_buffer_size(reg1)
                val2 = self.__determine_buffer_size(reg2)
                print(f"\nCondition for safe usage:\n" + \
                      f"{self.c_functions_database[f_name]['parameter_names'][ind1]}" + \
                      f" {matches.group(2)} " + \
                      f"{self.c_functions_database[f_name]['parameter_names'][ind2]}\n")
                match matches.group(2):
                    case '>=' | '>':
                        if val1 < val2:
                            vulnerable = True
                            print(bcolors.FAIL + \
                                  "Warning: Risk of Stack buffer Overflow from bad function parameterization" + \
                                  bcolors.ENDC)
                            print(f"{self.c_functions_database[f_name]['parameter_names'][ind1]} (={val1}) < " + \
                                  f"{self.c_functions_database[f_name]['parameter_names'][ind2]} (={val2})")
                    case '<=' | '<':
                        if val1 > val2:
                            vulnerable = True
                            print(bcolors.FAIL + \
                                  "Warning: Risk of Stack buffer Overflow from bad function parameterization" + \
                                  bcolors.ENDC)
                            print(f"{self.c_functions_database[f_name]['parameter_names'][ind1]} (={val1}) > " + \
                                  f"{self.c_functions_database[f_name]['parameter_names'][ind2]} (={val2})")
                    case '=':
                        if val1 != val2:
                            vulnerable = True
                            print(bcolors.FAIL + \
                                  "Warning: Risk of Stack buffer Overflow from bad function parameterization" + \
                                  bcolors.ENDC)
                            print(f"{self.c_functions_database[f_name]['parameter_names'][ind1]} (={val1}) != " + \
                                  f"{self.c_functions_database[f_name]['parameter_names'][ind2]} (={val2})")
                    case _:
                        print("Could not interpret condition. Please check the json file.")
        if not vulnerable:
            print(bcolors.OKGREEN + \
                  "No obvious stack buffer overflow vulnerabilities were detected from the function parameters." + \
                  bcolors.ENDC)

    def __display_function_name(self, f_name):
        """
        Auxiliary function to display_found_arguments
        Displays the function name properly formatted
        e.g.: 'function (arg1, arg2, ...)'

        Returns:
            str: Properly formatted function name
        """
        parameter_names = self.c_functions_database[f_name]['parameter_names']
        result = "\'"  + f_name + " ("
        for par in parameter_names:
            result += par + ", "
        result = result[:-2] + ")\'"
        return result

    def __display_found_arguments(self, f_call_addr):
        f_name = self.found_c_function_calls[f_call_addr]
        number_arguments = self.c_functions_database[f_name]['parameters']
        if number_arguments > len(self.param_order):
            print("Arguments saved on the stack will not be displayed")
        print(f"Arguments found for function {self.__display_function_name(f_name)}")
        for i, register in enumerate(self.param_order[:number_arguments]):
            param = self.c_functions_database[f_name]['parameter_names'][i]
            if "buffer" in param:
                print(f"{param}: {register} = {self.registers[register]} (Size = {self.__determine_buffer_size(register)})")
            else:
                print(f"{param}: {register} = {self.registers[register]}")


    def __test(self, f_call_addr):
        self.__determine_f_register_values(f_call_addr)
        self.__display_found_arguments(f_call_addr)
        self.__verify_argument_validity(f_call_addr)


    def full_analysis(self):
        """
        Runs a full analysis on the disassembled binary file.
        It searches for c-family functions according to a list of functions specified in the file
        c_functions.json. It then alerts if any of the functions detected are specified as unsafe, and analyses
        the disassembled code to determine the parameters passed on to those functions. If the functions are
        found to be badly parameterized it gives a warning specifying which parameters are the offending ones and
        how they are badly parameterized.
        """
        self.__c_family_detector()
        print("Found the following C-family functions:\n"+\
              f"{list(self.found_c_function_calls.values())}")
        for (f_addr, f_name) in self.found_c_function_calls.items():
            if self.c_functions_database[f_name]['safe'] == "no":
                print(bcolors.FAIL + \
                      f"\nWarning: Risk of Stack Buffer Overflow.\nUnsafe function \'{f_name}\' is called." + \
                      bcolors.ENDC)
                print(f"\nAnalysing \'{self.found_c_function_calls[f_addr]}\' at Address: 0x{f_addr}:")
                self.__determine_f_register_values(f_addr)
                self.__display_found_arguments(f_addr)
            else:
                print(f"\nAnalysing {self.found_c_function_calls[f_addr]} at Address: 0x{f_addr}:")
                self.__determine_f_register_values(f_addr)
                self.__display_found_arguments(f_addr)
                self.__verify_argument_validity(f_addr)
