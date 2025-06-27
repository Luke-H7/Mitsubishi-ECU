import ghidra_bridge

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

def main():
    print('Mitsubishi Table finding tool for SH2 based ECUs')
    print('\tLoading Ghidra Bridge. Current Offset: ', end='')
    # creates the bridge and loads the flat API into the global namespace
    b = ghidra_bridge.GhidraBridge(namespace=globals())
    print(getState().getCurrentAddress().getOffset())

    # ghidra module implicitly loaded at the same time as the flat API
    ghidra.program.model.data.DataUtilities.isUndefinedData(
        currentProgram, currentAddress)

    #Create transaction for our changes and wrapped the whole script in a try catch
    transaction = currentProgram.startTransaction("Table Transaction")
    try:
        table_read_function = getFunctionAt(toAddr(0xC28))
        new_param = ghidra.program.model.listing.ParameterImpl(
            "table_address", ghidra.program.model.data.PointerDataType(), currentProgram)
        table_read_function.replaceParameters(ghidra.program.model.listing.Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                                                  True, ghidra.program.model.symbol.SourceType.USER_DEFINED, new_param)
        refs = getReferencesTo(toAddr(0xC28))

        for f in refs:
            print(f)
            print(type(f))
            print(f.getFromAddress())
            break
        print(ghidra.program.util.FunctionParameterFieldLocation())
    except Exception as e:
        print('ERROR: %s' % e)
    finally:
        #Commit changes always
        currentProgram.endTransaction(transaction, True)

#Check if autonaalysis used compiler parameterid
if __name__ == '__main__':
    main()
