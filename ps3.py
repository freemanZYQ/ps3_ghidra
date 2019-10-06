#TODO write a description for this script
#@author 
#@category Analysis
#@keybinding 
#@menupath 
#@toolbar 


#TODO Add User Code Here

from ghidra.program.model.data import StructureDataType, CategoryPath, DataTypeConflictHandler, UnsignedCharDataType, UnsignedShortDataType, UnsignedIntegerDataType, Pointer32DataType
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.lang import RegisterValue
from java.math import BigInteger
import xml.etree.ElementTree as ET
import os
import sys

print os.getcwd()


tree = ET.parse('ps3.xml')
root_xml = tree.getroot()


dataTypeManager = currentProgram.getDataTypeManager()
memory = currentProgram.getMemory()
listing = currentProgram.getListing()

libstubstruc = StructureDataType(CategoryPath.ROOT, "_scelibstub", 0)
libstubstruc.add(UnsignedCharDataType(), 1, "structsize", "")
libstubstruc.add(UnsignedCharDataType(), 1, "reserved1", "")
libstubstruc.add(UnsignedShortDataType(), 2, "version", "")
libstubstruc.add(UnsignedShortDataType(), 2, "attribute", "")
libstubstruc.add(UnsignedShortDataType(), 2, "nfunc", "")
libstubstruc.add(UnsignedShortDataType(), 2, "nvar", "")
libstubstruc.add(UnsignedShortDataType(), 2, "ntlsvar", "")
libstubstruc.add(UnsignedCharDataType(), 4, "reserved2", "")
libstubstruc.add(Pointer32DataType(), 4, "libname", "")
libstubstruc.add(Pointer32DataType(), 4, "func_nidtable", "")
libstubstruc.add(Pointer32DataType(), 4, "func_table", "")
libstubstruc.add(Pointer32DataType(), 4, "var_nidtable", "")
libstubstruc.add(Pointer32DataType(), 4, "var_table", "")
libstubstruc.add(Pointer32DataType(), 4, "tls_nidtable", "")
libstubstruc.add(Pointer32DataType(), 4, "tls_table", "")

libentstruc = StructureDataType(CategoryPath.ROOT, "_scelibent", 0)
libentstruc.add(UnsignedCharDataType(), 1, "structsize", "")
libentstruc.add(UnsignedCharDataType(), 1, "reserved", "")
libentstruc.add(UnsignedShortDataType(), 2, "version", "")
libentstruc.add(UnsignedShortDataType(), 2, "attribute", "")
libentstruc.add(UnsignedShortDataType(), 2, "nfunc", "")
libentstruc.add(UnsignedShortDataType(), 2, "nvar", "")
libentstruc.add(UnsignedShortDataType(), 2, "ntlsvar", "")
libentstruc.add(UnsignedCharDataType(), 4, "reserved", "")
libentstruc.add(Pointer32DataType(), 4, "libname", "")
libentstruc.add(Pointer32DataType(), 4, "nidtable", "")
libentstruc.add(Pointer32DataType(), 4, "addtable", "")

dataTypeManager.addDataType(libstubstruc, DataTypeConflictHandler.REPLACE_HANDLER)
dataTypeManager.addDataType(libentstruc, DataTypeConflictHandler.REPLACE_HANDLER)


def get_name_for_nid(nid, library):
	for group in root_xml:
		#print "%s - %s" % (group.attrib['name'], library)
		if group.attrib['name'] == library:
			for entry in group:
				if int(entry.attrib['id'], 16) == nid:
					return entry.attrib['name']
                    
def loadExports(memBlock):
	addr = memBlock.getStart()
	while addr < memBlock.getEnd():
		print addr
        
		nfunc = memory.getShort(addr.add(0x6))
        
		func_libname  = toAddr( memory.getInt(addr.add(0x10)) )
		func_nidtable = toAddr( memory.getInt(addr.add(0x14)) )
		func_table    = toAddr( memory.getInt(addr.add(0x18)) )
        
		try:
			listing.createData(func_libname, StringDataType())
		except:
			pass
            
		libname = listing.getDataAt(func_libname).getDefaultValueRepresentation().encode('utf-8').strip("\"")
		print libname
        
		for x in xrange(nfunc):
			func_nid  = memory.getInt(func_nidtable) & 0xffffffff
			func_ptr  = toAddr(memory.getInt(func_table))
            

			try:
				listing.createData(func_nidtable, UnsignedIntegerDataType())
			except:
				pass
			try:
				listing.createData(func_table, Pointer32DataType())
			except:
				pass

			func_name = get_name_for_nid(func_nid, libname)
			print func_name
			if func_name != None:
				setEOLComment(func_nidtable, func_name)
				opd_func_ptr = toAddr( memory.getInt(func_ptr) )
				func = listing.getFunctionAt(opd_func_ptr)
				if func != None:
					func.setName(func_name, SourceType.ANALYSIS)
				else:
					createFunction(opd_func_ptr, func_name)

			func_nidtable = func_nidtable.add(0x4)
			func_table    = func_table.add(0x4)
			

		try:
			listing.createData(addr, libentstruc)
		except:
			pass
		
		addr = addr.add(0x1C)

def loadImports(memBlock):
	addr = memBlock.getStart()
	while addr < memBlock.getEnd():
		print addr

		nfunc = memory.getShort(addr.add(0x6))

		func_libname  = toAddr( memory.getInt(addr.add(0x10)) )
		func_nidtable = toAddr( memory.getInt(addr.add(0x14)) )
		func_table    = toAddr( memory.getInt(addr.add(0x18)) )

		try:
			listing.createData(func_libname, StringDataType())
		except:
			pass

		libname = listing.getDataAt(func_libname).getDefaultValueRepresentation().encode('utf-8').strip("\"")
		print libname

		for x in xrange(nfunc):
			func_nid  = memory.getInt(func_nidtable) & 0xffffffff
			func_ptr  = toAddr(memory.getInt(func_table))

			try:
				listing.createData(func_nidtable, UnsignedIntegerDataType())
			except:
				pass
			try:
				listing.createData(func_table, Pointer32DataType())
			except:
				pass

			func_name = get_name_for_nid(func_nid, libname)
			print func_name
			if func_name != None:
				worked = setEOLComment(func_nidtable, func_name)
				print worked
				func = listing.getFunctionAt(func_ptr)
				if func != None:
					func.setName(func_name, SourceType.ANALYSIS)
				else:
					createFunction(func_ptr, func_name)

			func_nidtable = func_nidtable.add(0x4)
			func_table    = func_table.add(0x4)
			

		try:
			listing.createData(addr, libstubstruc)
		except:
			pass
		
		addr = addr.add(0x2C)
	
# iterate each section to find libstub and libent
for memBlock in memory.getBlocks():
	if not memBlock.isInitialized():
		continue
	print("Checking section: %s" % memBlock.getName())
	sectaddr = memBlock.getStart()
	print sectaddr
	structsize = memBlock.getByte(sectaddr) & 0xff
	print structsize
	if structsize > memBlock.getSize():
		continue
	structsize2 = memBlock.getByte(sectaddr.add(structsize)) & 0xff
	print structsize2
	if structsize == structsize2:
		if structsize == 0x1C:
			loadExports(memBlock)
		elif structsize == 0x2C:
			loadImports(memBlock)
			
entry_point = memory.getLong(memory.getBlocks()[0].getStart().add(0x18))
print "%x" % entry_point
opd_sect = memory.getBlock(toAddr(entry_point))
addr = opd_sect.getStart()

while addr < opd_sect.getEnd():
	func_ptr = toAddr( memory.getInt(addr) )
	func_toc = memory.getInt(addr.add(0x4))
	createFunction(func_ptr, None)
	func = getFunctionAt(func_ptr)
	func_min = func.getBody().getMinAddress()
	func_max = func.getBody().getMaxAddress()
	try:
		createDWord(addr)
	except:
		pass
	try:
		createDWord(addr.add(0x4))
	except:
		pass

	r2reg = currentProgram.getRegister("r2")
	tocValue = RegisterValue(r2reg, BigInteger.valueOf(func_toc))
	currentProgram.getProgramContext().setRegisterValue(func_min, func_max, tocValue)
	addr = addr.add(0x18)
