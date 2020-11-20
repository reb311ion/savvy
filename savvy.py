#Drltrace log importer for Ghidra.
#@author @reb311ion
#@keybinding shift L
#@category Analysis
#@toolbar savvy.png

from ghidra.program.model.address.Address import *
from ghidra.program.model.listing import *
from ghidra.program.model.symbol import *
from ghidra.program.model.address import *
from ghidra.program.model.mem import *
from ghidra.program.model.symbol.RefType import *
from ghidra.program.model.symbol.SourceType import *
from ghidra.program.model.symbol.SymbolUtilities import *
from ghidra.program.model.symbol.ReferenceManager import *
from ghidra.app.services import DataTypeManagerService
from ghidra.program.model.symbol import FlowType
from ghidra.program.model.data import DataTypeManager
from ghidra.app.cmd.function import ApplyFunctionDataTypesCmd
from ghidra.program.database.mem import FileBytes
from ghidra.util.task import TaskMonitor
from ghidra.framework.cmd import Command
from ghidra.app.cmd.memory import AddInitializedMemoryBlockCmd


"""
create new section
parse log
WHILE not end of log
BEGIN
    IF call is an indirect call
    BEGIN 
        add api function
        add api label
        add api bookmark
        set api refrence
    END IF
END WHILE
applay function data types
"""


offset = None
length = 0
current_offset = 0

def get_caller_from_return(addr):
    return getInstructionAt(toAddr(addr)).previous.getAddress()

def add_label(addr, label_text):
    symbolTable = currentProgram.getSymbolTable()
    symbolTable.createLabel(addr, label_text, USER_DEFINED)

def add_bookmark(addr, bookmark_text):
    bm = currentProgram.getBookmarkManager()
    bm.setBookmark(addr, "Info", "savvy", bookmark_text)


def apply_function_data_types():
    tool = state.getTool()
    service = tool.getService(DataTypeManagerService)
    dataTypeManagers = list(service.getDataTypeManagers())
    set = AddressSet()
    set.addRange(currentProgram.minAddress, currentProgram.maxAddress)
    s = ApplyFunctionDataTypesCmd(dataTypeManagers, set, SourceType.IMPORTED, False, True)
    s.applyTo(currentProgram, monitor)


def create_new_section(name=".diat", description="Dynamically resolve Imports", block_count=5, fill_with_byte=0xc3):
    global offset
    global length
    blocks = currentProgram.getMemory().getBlocks()
    offset = toAddr(int(round((int(str(blocks[-1].end), 16) + 1000), -3)))
    length = (int((str(blocks[1].getStart())[-4:]), 16) * block_count) - 0x200
    command = AddInitializedMemoryBlockCmd(name, description, description, offset, length, True, True, True, False, fill_with_byte, False)
    currentProgram.startTransaction(command.getName())
    command.applyTo(currentProgram)


def add_api_function(name):
    global current_offset
    api_offset = offset.add(current_offset)
    createFunction(api_offset, name)
    current_offset += 1
    return api_offset


def add_api_reference(caller_addr, api_addr):
    try:
        api_name = getFunctionAt(api_addr).name
    except:
        print api_addr
        exit(-1)
    add_label(caller_addr, api_name)
    add_bookmark(caller_addr, "Call To: {}".format(api_name))
    refmanager = currentProgram.referenceManager
    refmanager.addMemoryReference(caller_addr, api_addr, CALL_OVERRIDE_UNCONDITIONAL, USER_DEFINED, -1)


def parse_log_file(file_path):
    base_addr = int(currentProgram.getMinAddress().toString(), 16)
    api_dict = {}
    log = ""
    with open(file_path, "r") as log_file:
        log = log_file.read().split("\n")
    
    for line in log:
        if ".dll!" in line:
            api_name = line.split("!")[-1].split(" ")[0]
            if not api_name in api_dict.keys():
                api_dict[api_name] = []
        
        if "return" in line and not api_name in line:
            try:
                return_value = line.split(":")[-1].split(" ")[0]
                return_value = base_addr + int(return_value, 16)
                if not return_value in api_dict[api_name]:
                    api_dict[api_name].append(return_value)
            except:
                pass

    return api_dict


if __name__ == '__main__':
    log_path = askFile("Drltrace log", "Choose file:")
    log_path = str(log_path)
    api_dict = parse_log_file(log_path)
    create_new_section()

    for api_name in api_dict:
        for return_value in api_dict[api_name]:
            caller_address = get_caller_from_return(return_value)
            if getInstructionAt(caller_address).flowType == COMPUTED_CALL:
                api_addr = add_api_function(api_name)
                add_api_reference(caller_address, api_addr)
    apply_function_data_types()