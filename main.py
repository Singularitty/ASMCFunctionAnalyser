#!/bin/python3

# System modules
import argparse

# User modules
import analyser as dp


def get_arguments():
    """
    Grabs arguments from stdin using argparse library

    Returns:
        argparse: object containing the arguments given in the terminal
    """

    arg_parser = argparse.ArgumentParser(prog='c_func_detector', description='Find sensitive sinks in C binaries')
    arg_parser.add_argument('file', type=str, help='File to be analysed', default=None)
    return arg_parser.parse_args()


# noinspection SpellCheckingInspection
class Interface:
    """
    Provides a programming interface to the program
    """

    def __init__(self):
        self.file_name = None
        self.__set_file_name()
        self.disassembler = None
        self.parser = None
        self.analyser = None
        self.running_status = True
        self.__init_sequence()

    def __set_file_name(self):
        """
        Sets the file name of the elf binary to be disassembled and analysed
        """
        args = get_arguments()
        self.file_name = args.file

    def __quit(self):
        """
        Sets the running status of the program to False, causing it to exit
        """
        self.running_status = False

    def __disassemble_file(self):
        self.disassembler = dp.Disassembler(self.file_name)

    def __init_parser(self):
        self.parser = dp.Parser(self.disassembler.code)

    def __init_sequence(self):
        """
        Sequence of functions ran at start of program to initialize the class parameters.
        This includes disassembling the specified file with objdump and parsing the output.
        It is also ran when the user specifies another file for analysis.
        """
        self.__disassemble_file()
        self.__init_parser()

    def __display_code_section(self):
        """
        Displays a section of disassembled code from a function in the .text section.
        This can be displayed backwards or normally.
        """
        func = input("Function name: ")
        start_addr = input("Starting address: ")
        back = input("Backwards (Y/n): ")
        if back.upper() == 'YES' or back.upper() == "Y" or back == '':
            back = True
        else:
            back = False
        sequence = self.parser.get_instruction_range(func, start_addr, back)
        for i in sequence:
            print(i)

    def status(self):
        """
        Returns the program status
        """
        return self.running_status

    def execute(self, usr_command):
        """
        Matches user commands to program function calls, providing an interface between the user and the program
        """
        match usr_command:
            case 'q' | 'quit' | 'exit':
                self.running_status = False
            case 'disas' | 'disassemble':
                if self.disassembler is None:
                    self.__disassemble_file()
                self.disassembler.display_disassembled_code()
            case 'function' | 'f' | 'functions':
                if self.parser is None:
                    self.__init_parser()
                self.parser.display_functions()
            case 'call' | 'calls':
                if self.parser is None:
                    self.__init_parser()
                self.parser.display_calls()
            case 'file':
                self.file_name = input("New file path: ")
                self.__init_sequence()
            case 'get instruction' | 'instruction at' | 'instruction':
                address = input("Specify instruction address: ")
                print(self.parser.return_instruction_at(address))
            case 'get sequence' | 'sequence':
                self.__display_code_section()
            case 'test':
                a = dp.Analyser(self.parser)
                a.test(input('Address: '))
            case 'h' | 'help' | _:
                print("\'quit\' to exit the program")


# Program Entry Point
if __name__ == '__main__':

    program = Interface()

    while program.status():
        usr_input = input(':')
        program.execute(usr_input)
