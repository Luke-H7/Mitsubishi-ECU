import ghidra_bridge

"""
Helper function thats converts and int to a Ghidra Address type
"""
def getAddress(offset):
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset)

"""
Creates and labels ROM_ID at specified offset.
Returns the data contained at that offset
"""
def getRomID(address):
    #Convert offset to address type
    addr = getAddress(address)

    #Create DWord for ROM ID
    romid = createDWord(addr)

    #Label newly created DWORD
    createLabel(addr, 'ROM_ID', True)
    
    #Return the data at offset contained in the new DWORD
    return romid.getDefaultValueRepresentation()

"""
Main function fo SH2 Auto Analysis.
Currently supports locating Unique ROMID
"""
def sh2_main():
    print('\tRunning Mitsubishi SuperH ECU Analysis')

    #Get and print Unique ROM identifier. Always located at 0xF52
    romid = getRomID(0xF52)
    print('\t\tROM ID is: %s' % romid)


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
            print('\t\tProcessor is SuperH')
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
