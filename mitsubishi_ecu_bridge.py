import ghidra_bridge


"""
Creates and labels ROM_ID at specified offset.
Returns the data contained at that offset
"""
def getRomID(address):
    #Create DWord for ROM ID
    romid = createDWord(address)

    #Label newly created DWORD
    createLabel(address, 'ROM_ID', True)
    
    #Return the data at offset contained in the new DWORD
    return romid.getDefaultValueRepresentation()

def createStructures():
    map_3d_byte = ghidra.program.model.data.StructureDataType('map_3d_byte', 0)
    map_3d_byte.add(ghidra.program.model.data.ByteDataType(), 'dimensions', '')
    map_3d_byte.add(ghidra.program.model.data.ByteDataType(), 'adder', '')
    map_3d_byte.add(ghidra.program.model.data.DWordDataType(), 'index_x', '')
    map_3d_byte.add(ghidra.program.model.data.DWordDataType(), 'index_y', '')
    map_3d_byte.add(ghidra.program.model.data.ByteDataType(), 'nrows', '')
    map_3d_byte.add(ghidra.program.model.data.ArrayDataType(
        ghidra.program.model.data.ByteDataType(), 1, 1), 'data', '')

    map_3d_word = ghidra.program.model.data.StructureDataType('map_3d_word', 0)
    map_3d_word.add(ghidra.program.model.data.WordDataType(), 'dimensions', '')
    map_3d_word.add(ghidra.program.model.data.WordDataType(), 'adder', '')
    map_3d_word.add(ghidra.program.model.data.DWordDataType(), 'index_x', '')
    map_3d_word.add(ghidra.program.model.data.DWordDataType(), 'index_y', '')
    map_3d_word.add(ghidra.program.model.data.WordDataType(), 'nrows', '')
    map_3d_word.add(ghidra.program.model.data.ArrayDataType(
        ghidra.program.model.data.WordDataType(), 1, 1), 'data', '')

    map_2d_word = ghidra.program.model.data.StructureDataType('map_2d_word', 0)
    map_2d_word.add(ghidra.program.model.data.WordDataType(), 'dimensions', '')
    map_2d_word.add(ghidra.program.model.data.WordDataType(), 'adder', '')
    map_2d_word.add(ghidra.program.model.data.DWordDataType(), 'index_x', '')
    map_2d_word.add(ghidra.program.model.data.ArrayDataType(
        ghidra.program.model.data.WordDataType(), 1, 1), 'data', '')

    map_2d_byte = ghidra.program.model.data.StructureDataType('map_2d_byte', 0)
    map_2d_byte.add(ghidra.program.model.data.ByteDataType(), 'dimensions', '')
    map_2d_byte.add(ghidra.program.model.data.ByteDataType(), 'adder', '')
    map_2d_byte.add(ghidra.program.model.data.DWordDataType(), 'index_x', '')
    map_2d_byte.add(ghidra.program.model.data.ArrayDataType(
        ghidra.program.model.data.ByteDataType(), 1, 1), 'data', '')

    axis_table = ghidra.program.model.data.StructureDataType('axis_table', 0)
    axis_table.add(ghidra.program.model.data.DWordDataType(), 'output', '')
    axis_table.add(ghidra.program.model.data.DWordDataType(), 'input', '')
    axis_table.add(ghidra.program.model.data.WordDataType(), 'length', '')
    axis_table.add(ghidra.program.model.data.ArrayDataType(
        ghidra.program.model.data.WordDataType(), 1, 1), 'data', '')

    createData(toAddr(0x4b68), map_3d_byte)
    createData(toAddr(0x5ed2), map_3d_word)
    createData(toAddr(0x4c08), map_2d_byte)
    createData(toAddr(0x395c), map_2d_word)
    createData(toAddr(0x62e0), axis_table)

def createVectorTable():
    i = 0
    while i < 0x400:
        try:
            vector = createData(toAddr(i), ghidra.program.model.data.Pointer32DataType())
            #Skip the stack pointers
            if i != 0x04 and i != 0x0C:
                createFunction(vector.getValue(), "")
        except:
            pass
        i += 4

"""
Main function fo SH2 Auto Analysis.
Currently supports locating Unique ROMID
"""
def sh2_main():
    print('\tRunning Mitsubishi SuperH ECU Analysis')

    #Get and print Unique ROM identifier. Always located at 0xF52
    #romid = getRomID(toAddr(0xF52))
    #print('\t\tROM ID is: %s' % romid)

    #Create segment for RAM. Passing any exceptions in case these regions already exist
    try:
        print("\t\tCreating RAM segment at 0xFFFF600 with length 0x8000")
        createMemoryBlock('Data', toAddr(0xFFFF6000), None, 0x8000, False)
    except:
        pass

    #Create segment for Registers. Passing any exceptions in case these regions already exist
    try:
        print("\t\tCreating Hardware register segment at 0xFFFFE400 with length 0x1460")
        createMemoryBlock('Reg', toAddr(0xFFFFE400), None, 0x1460, False)
    except:
        pass

    print('Creating constant arrays')
    createData(toAddr(0xF44), ghidra.program.model.data.ArrayDataType(
        ghidra.program.model.data.WordDataType(), 8, 1))
    createData(toAddr(0xF6A), ghidra.program.model.data.ArrayDataType(
        ghidra.program.model.data.DWordDataType(), 8, 1))
    createData(toAddr(0xF8A), ghidra.program.model.data.ArrayDataType(
        ghidra.program.model.data.WordDataType(), 8, 1))
    createData(toAddr(0xF9A), ghidra.program.model.data.ArrayDataType(
        ghidra.program.model.data.WordDataType(), 8, 1))
    createData(toAddr(0xFAA), ghidra.program.model.data.ArrayDataType(
        ghidra.program.model.data.WordDataType(), 8, 1))
    createData(toAddr(0xFBA), ghidra.program.model.data.ArrayDataType(
        ghidra.program.model.data.WordDataType(), 8, 1))
    createData(toAddr(0xFCA), ghidra.program.model.data.ArrayDataType(
        ghidra.program.model.data.WordDataType(), 8, 1))
    createData(toAddr(0xFDA), ghidra.program.model.data.ArrayDataType(
        ghidra.program.model.data.WordDataType(), 8, 1))
    createData(toAddr(0xFDA), ghidra.program.model.data.ArrayDataType(
        ghidra.program.model.data.WordDataType(), 8, 1))
    createData(toAddr(0xFEA), ghidra.program.model.data.ArrayDataType(
        ghidra.program.model.data.WordDataType(), 8, 1))
    createData(toAddr(0xFFA), ghidra.program.model.data.ArrayDataType(
        ghidra.program.model.data.WordDataType(), 8, 1))
    createData(toAddr(0x100A), ghidra.program.model.data.ArrayDataType(
        ghidra.program.model.data.WordDataType(), 8, 1))
    print('Test data array')
    print(getDataAt(toAddr(0xF44)))

    print('Creating Vector Table')
    createVectorTable()
    print('Creating Structures')
    #createStructures()
    analyzeAll(currentProgram)


def main():
    print('Mitsubishi ECU Auto Analysis Tool for Ghidra')
    print('\tLoading Ghidra Bridge. Current Offset: ', end='')
    # creates the bridge and loads the flat API into the global namespace
    b = ghidra_bridge.GhidraBridge(namespace=globals())
    print(getState().getCurrentAddress().getOffset())

    # ghidra module implicitly loaded at the same time as the flat API
    ghidra.program.model.data.DataUtilities.isUndefinedData(
        currentProgram, currentAddress)

    #Create transaction for our changes and wrapped the whole script in a try catch
    transaction =currentProgram.startTransaction("Mitsubishi Auto Analysis Transaction")
    try:
        print('\tChecking selected processor')

        #Get language and processor set when file was loaded
        language = currentProgram.getLanguage()
        processor = language.getProcessor()

        #Use the processor to check if auto analysis is supported
        if str(processor) == 'SuperH':
            #Process is SH-2 so run SuperH Analysis
            print('\t\tProcessor is SuperH\n')
            sh2_main()
        else:
            print('\t\tProcessor is unsupported')
    except Exception as e:
        print('ERROR: %s' % e)
    finally:
        #Commit changes always
        currentProgram.endTransaction(transaction, True)


if __name__ == '__main__':
    main()
