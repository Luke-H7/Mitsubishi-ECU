//Mitsubishi ECU Auto Analysis Tool for Ghidra
//@author Luke Hobley
//@category Analysis.Mitsubishi
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.*;
import java.util.Arrays;

public class mitsubishi_ecu extends GhidraScript {

	private void createByteRegister(int address, String label, String comment) throws Exception {
		createByte(toAddr(address));
		createLabel(toAddr(address), label, true);
		setPlateComment​(toAddr(address), comment);

		return;
	}

	private void createWordRegister(int address, String label, String comment) throws Exception {
		createWord(toAddr(address));
		createLabel(toAddr(address), label, true);
		setPlateComment​(toAddr(address), comment);

		return;
	}

	private void createDWordRegister(int address, String label, String comment) throws Exception {
		createDWord(toAddr(address));
		createLabel(toAddr(address), label, true);
		setPlateComment​(toAddr(address), comment);

		return;
	}

	private void createByteRegisterArray(int address, int length, String label, String comment) throws Exception {
		ByteDataType byteData = new ByteDataType();
		ArrayDataType data = new ArrayDataType(byteData, length, 1);
		createData​(toAddr(address), data);
		createLabel(toAddr(address), label, true);
		setPlateComment​(toAddr(address), comment);

		return;
	}

	private String getRomID(int address, String label) throws Exception {
		createDWord(toAddr(address));
		createLabel(toAddr(address), label, true);

		Data data = getDataAt(toAddr(address));

		return data.getDefaultValueRepresentation();
	}

	private void createStructures() throws Exception {
		// Create 3d byte map
		Structure map_3d_byte = new StructureDataType("map_3d_byte", 0);
		map_3d_byte.add(new ByteDataType(), "dimensions", "");
		map_3d_byte.add(new ByteDataType(), "adder", "");
		map_3d_byte.add(new DWordDataType(), "index_x", "");
		map_3d_byte.add(new DWordDataType(), "index_y", "");
		map_3d_byte.add(new ByteDataType(), "nrows", "");
		ArrayDataType byteArr3D = new ArrayDataType(new ByteDataType(), 1, 1);
		map_3d_byte.add(byteArr3D, "data", "");

		// Create 3d word map
		Structure map_3d_word = new StructureDataType("map_3d_word", 0);
		map_3d_word.add(new WordDataType(), "dimensions", "");
		map_3d_word.add(new WordDataType(), "adder", "");
		map_3d_word.add(new DWordDataType(), "index_x", "");
		map_3d_word.add(new DWordDataType(), "index_y", "");
		map_3d_word.add(new WordDataType(), "nrows", "");
		ArrayDataType wordArr3D = new ArrayDataType(new WordDataType(), 1, 1);
		map_3d_word.add(wordArr3D, "data", "");

		// Create 2d byte map
		Structure map_2d_byte = new StructureDataType("map_2d_byte", 0);
		map_2d_byte.add(new ByteDataType(), "dimensions", "");
		map_2d_byte.add(new ByteDataType(), "adder", "");
		map_2d_byte.add(new DWordDataType(), "index_x", "");
		ArrayDataType byteArr2D = new ArrayDataType(new ByteDataType(), 1, 1);
		map_2d_byte.add(byteArr2D, "data", "");

		// Create 2d word map
		Structure map_2d_word = new StructureDataType("map_2d_word", 0);
		map_2d_word.add(new WordDataType(), "dimensions", "");
		map_2d_word.add(new WordDataType(), "adder", "");
		map_2d_word.add(new DWordDataType(), "index_x", "");
		ArrayDataType wordArr2D = new ArrayDataType(new WordDataType(), 1, 1);
		map_2d_word.add(wordArr2D, "data", "");

		// Create axis table
		Structure axis_table = new StructureDataType("axis_table", 0);
		axis_table.add(new DWordDataType(), "output", "");
		axis_table.add(new DWordDataType(), "input", "");
		axis_table.add(new WordDataType(), "length", "");
		ArrayDataType wordArrAxis = new ArrayDataType(new WordDataType(), 1, 1);
		axis_table.add(wordArrAxis, "data", "");

		createData​(toAddr(0x4b68), map_3d_byte);
		createData​(toAddr(0x5ed2), map_3d_word);
		createData​(toAddr(0x4c08), map_2d_byte);
		createData​(toAddr(0x395c), map_2d_word);
		createData​(toAddr(0x62e0), axis_table);
	}

	private void labelVector(int address, String label, String comment) throws Exception {
		createLabel(toAddr(address), label, true);
		setPlateComment​(toAddr(address), comment);

		Data vector = getDataAt(toAddr(address));
		if (vector.isPointer()) {
			Address addr = (Address) vector.getValue();
			Function func = getFunctionAt(addr);

			if (func == null) {
				Function newFunc = createFunction​(addr, comment);
			} else {
				if (func.getName().equals("")) {
					func.setName(comment, SourceType.ANALYSIS);
				}
			}

		}
	}

	private void createVectorTable(int length) throws Exception {
		Address currentAddress = toAddr(0x00);

		for (int i = 0; i < length; i++) {
			if (monitor.isCancelled()) {
				break;
			}
			Data vector = createData​(currentAddress, new Pointer32DataType());

			if (i == 1 || i == 3) {
				if (vector.isPointer()) {
					Address addr = (Address) vector.getValue();
					createLabel(addr, "init_stack_ptr", true);
					setPlateComment​(addr, "Initial stack pointer");
				}
			} else {
			}

			currentAddress = currentAddress.add(0x04);
		}
		labelVector(0x00000000, "v_power_on_pc", "init");
		labelVector(0x00000004, "v_power_on_sp", "stack");
		labelVector(0x00000008, "v_reset_pc", "reset_pc");
		labelVector(0x0000000C, "v_reset_sp", "stack");
		labelVector(0x00000010, "v_gen_ill_inst", "reset");
		labelVector(0x00000018, "v_slot_ill_inst", "slot_ill_inst");
		labelVector(0x00000024, "v_cpu_addr_err", "cpu_addr_err");
		labelVector(0x00000028, "v_dmac_addr_err", "dmac_addr_err");
		labelVector(0x0000002C, "NMI", "nmi");
		labelVector(0x00000030, "UBC", "userbreak");

		// Trap
		labelVector(0x00000080, "TRAP0", "trap");
		labelVector(0x00000084, "TRAP1", "trap");
		labelVector(0x00000088, "TRAP2", "trap");
		labelVector(0x0000008C, "TRAP3", "trap");
		labelVector(0x00000090, "TRAP4", "trap");
		labelVector(0x00000094, "TRAP5", "trap");
		labelVector(0x00000098, "TRAP6", "trap");
		labelVector(0x0000009C, "TRAP7", "trap");
		labelVector(0x000000A0, "TRAP8", "trap");
		labelVector(0x000000A4, "TRAP9", "trap");
		labelVector(0x000000A8, "TRAP10", "trap");
		labelVector(0x000000AC, "TRAP11", "trap");
		labelVector(0x000000B0, "TRAP12", "trap");
		labelVector(0x000000B4, "TRAP13", "trap");
		labelVector(0x000000B8, "TRAP14", "trap");
		labelVector(0x000000BC, "TRAP15", "trap");
		labelVector(0x000000C0, "TRAP16", "trap");
		labelVector(0x000000C4, "TRAP17", "trap");
		labelVector(0x000000C8, "TRAP18", "trap");
		labelVector(0x000000CC, "TRAP19", "trap");
		labelVector(0x000000D0, "TRAP20", "trap");
		labelVector(0x000000D4, "TRAP21", "trap");
		labelVector(0x000000D8, "TRAP22", "trap");
		labelVector(0x000000DC, "TRAP23", "trap");
		labelVector(0x000000E0, "TRAP24", "trap");
		labelVector(0x000000E4, "TRAP25", "trap");
		labelVector(0x000000E8, "TRAP26", "trap");
		labelVector(0x000000EC, "TRAP27", "trap");
		labelVector(0x000000F0, "TRAP28", "trap");
		labelVector(0x000000F4, "TRAP29", "trap");
		labelVector(0x000000F8, "TRAP30", "trap");
		labelVector(0x000000FC, "TRAP31", "trap");

		labelVector(0x00000100, "IRQ0", "irq0");
		labelVector(0x00000104, "IRQ1", "irq1");
		labelVector(0x00000108, "IRQ2", "irq2");
		labelVector(0x0000010C, "IRQ3", "irq3");
		labelVector(0x00000120, "DMAC0", "dmac0");
		labelVector(0x00000128, "DMAC1", "dmac1");
		labelVector(0x00000130, "DMAC2", "dmac2");
		labelVector(0x00000138, "DMAC3", "dmac3");
		labelVector(0x000002F0, "CMTI0", "cmti0");
		labelVector(0x000002F8, "ADI0", "adi0");
		labelVector(0x00000300, "CMTI1", "cmti1");
		labelVector(0x00000308, "ADI1", "adi1");
		labelVector(0x00000380, "ITI", "wdt_iti");
		// ATU0
		labelVector(0x00000140, "ITV1", "atu0_itv1");
		labelVector(0x00000150, "ICI0A", "atu0_ici0a");
		labelVector(0x00000158, "ICI0B", "atu0_ici0b");
		labelVector(0x00000160, "ICI0C", "atu0_ici0c");
		labelVector(0x00000168, "ICI0D", "atu0_ici0d");
		labelVector(0x00000170, "OVI0", "atu0_ovi0");
		// ATU1
		labelVector(0x00000180, "IMI1A", "atu1_imi1a");
		labelVector(0x00000184, "IMI1B", "atu1_imi1b");
		labelVector(0x00000188, "IMI1C", "atu1_imi1c");
		labelVector(0x0000018C, "IMI1D", "atu1_imi1d");
		labelVector(0x00000190, "IMI1E", "atu1_imi1e");
		labelVector(0x00000194, "IMI1F", "atu1_imi1f");
		labelVector(0x00000198, "IMI1G", "atu1_imi1g");
		labelVector(0x0000019C, "IMI1H", "atu1_imi1h");
		labelVector(0x000001A0, "OVI1A", "atu1_ovi1a");
		// ATU2
		labelVector(0x000001B0, "IMI2A", "atu2_imi2a");
		labelVector(0x000001B4, "IMI2B", "atu2_imi2b");
		labelVector(0x000001B8, "IMI2C", "atu2_imi2c");
		labelVector(0x000001BC, "IMI2D", "atu2_imi2d");
		labelVector(0x000001C0, "IMI2E", "atu2_imi2e");
		labelVector(0x000001C4, "IMI2F", "atu2_imi2f");
		labelVector(0x000001C8, "IMI2G", "atu2_imi2g");
		labelVector(0x000001CC, "IMI2H", "atu2_imi2h");
		labelVector(0x000001D0, "OVI2A", "atu2_ovi2a");
		// ATU3
		labelVector(0x000001E0, "IMI3A", "atu3_imi3a");
		labelVector(0x000001E4, "IMI3B", "atu3_imi3b");
		labelVector(0x000001E8, "IMI3C", "atu3_imi3c");
		labelVector(0x000001EC, "IMI3D", "atu3_imi3d");
		labelVector(0x000001F0, "OVI3", "atu3_ovi3");
		// ATU4
		labelVector(0x00000200, "IMI4A", "atu4_imi4a");
		labelVector(0x00000204, "IMI4B", "atu4_imi4b");
		labelVector(0x00000208, "IMI4C", "atu4_imi4c");
		labelVector(0x0000020C, "IMI4D", "atu4_imi4d");
		labelVector(0x00000210, "OVI4", "atu4_ovi4");
		// ATU5
		labelVector(0x00000220, "IMI5A", "atu5_imi5a");
		labelVector(0x00000224, "IMI5B", "atu5_imi5b");
		labelVector(0x00000228, "IMI5C", "atu5_imi5c");
		labelVector(0x0000022C, "IMI5D", "atu5_imi5d");
		labelVector(0x00000230, "OVI5", "atu5_ovi5");
		// ATU6
		labelVector(0x00000240, "CMI6A", "atu6_cmi6a");
		labelVector(0x00000244, "CMI6B", "atu6_cmi6b");
		labelVector(0x00000248, "CMI6C", "atu6_cmi6c");
		labelVector(0x0000024C, "CMI6D", "atu6_cmi6d");
		// ATU7
		labelVector(0x00000250, "CMI7A", "atu7_cmi7a");
		labelVector(0x00000254, "CMI7B", "atu7_cmi7b");
		labelVector(0x00000258, "CMI7C", "atu7_cmi7c");
		labelVector(0x0000025C, "CMI7D", "atu7_cmi7d");
		// ATU8
		labelVector(0x00000260, "OSI8A", "atu8_osi8a");
		labelVector(0x00000264, "OSI8B", "atu8_osi8b");
		labelVector(0x00000268, "OSI8C", "atu8_osi8c");
		labelVector(0x0000026C, "OSI8D", "atu8_osi8d");
		labelVector(0x00000270, "OSI8E", "atu8_osi8e");
		labelVector(0x00000274, "OSI8F", "atu8_osi8f");
		labelVector(0x00000278, "OSI8G", "atu8_osi8g");
		labelVector(0x0000027C, "OSI8H", "atu8_osi8h");
		labelVector(0x00000280, "OSI8I", "atu8_osi8i");
		labelVector(0x00000284, "OSI8J", "atu8_osi8j");
		labelVector(0x00000288, "OSI8K", "atu8_osi8k");
		labelVector(0x0000028C, "OSI8L", "atu8_osi8l");
		labelVector(0x00000290, "OSI8M", "atu8_osi8m");
		labelVector(0x00000294, "OSI8N", "atu8_osi8n");
		labelVector(0x00000298, "OSI8O", "atu8_osi8o");
		labelVector(0x0000029C, "OSI8P", "atu8_osi8p");
		// ATU9
		labelVector(0x000002A0, "CMI9A", "atu9_cmi9a");
		labelVector(0x000002A4, "CMI9B", "atu9_cmi9b");
		labelVector(0x000002A8, "CMI9C", "atu9_cmi9c");
		labelVector(0x000002AC, "CMI9D", "atu9_cmi9d");
		labelVector(0x000002B0, "CMI9E", "atu9_cmi9e");
		labelVector(0x000002B8, "CMI9F", "atu9_cmi9f");
		// ATU10
		labelVector(0x000002C0, "CMI10A", "atu10_cmi10a");
		labelVector(0x000002C8, "CMI10B", "atu10_cmi10b");
		labelVector(0x000002D0, "ICI10A", "atu10_ici10a");
		// ATU11
		labelVector(0x000002E0, "IMI11A", "atu11_imi11a");
		labelVector(0x000002E8, "IMI11B", "atu11_imi11b");
		labelVector(0x000002EC, "OVI11", "atu11_ovi11");
		// SCI0
		labelVector(0x00000320, "ERI0", "sci0_eri0");
		labelVector(0x00000324, "RXI0", "sci0_rxi0");
		labelVector(0x00000328, "TXI0", "sci0_txi0");
		labelVector(0x0000032C, "TEI0", "sci0_tei0");
		// SCI1
		labelVector(0x00000330, "ERI1", "sci1_eri1");
		labelVector(0x00000334, "RXI1", "sci1_rxi1");
		labelVector(0x00000338, "TXI1", "sci1_txi1");
		labelVector(0x0000033C, "TEI1", "sci1_tei1");
		// SCI2
		labelVector(0x00000340, "ERI2", "sci2_eri2");
		labelVector(0x00000344, "RXI2", "sci2_rxi2");
		labelVector(0x00000348, "TXI2", "sci2_txi2");
		labelVector(0x0000034C, "TEI2", "sci2_tei2");
		// SCI3
		labelVector(0x00000350, "ERI3", "sci3_eri3");
		labelVector(0x00000354, "RXI3", "sci3_rxi3");
		labelVector(0x00000358, "TXI3", "sci3_txi3");
		labelVector(0x0000035C, "TEI3", "sci3_tei3");
		// SCI4
		labelVector(0x00000360, "ERI4", "sci4_eri4");
		labelVector(0x00000364, "RXI4", "sci4_rxi4");
		labelVector(0x00000368, "TXI4", "sci4_txi4");
		labelVector(0x0000036C, "TEI4", "sci4_tei4");
		// HCAN
		labelVector(0x00000370, "ERS", "hcan_ers");
		labelVector(0x00000374, "OVR", "hcan_ovr");
		labelVector(0x00000378, "RM", "hcan_rm");
		labelVector(0x0000037C, "SLE", "hcan_sle");

	}

	private void fixConstants() throws Exception {
		int length = 0x1000;
		Address currentAddress = toAddr(0x1500);
		for (int i = 0; i < length; i++) {
			if (monitor.isCancelled()) {
				break;
			}

			createData​(currentAddress, new WordDataType());
			currentAddress = currentAddress.add(0x02);
		}
	}

	private void sh2LabelRegisters() throws Exception {
		// Interrupt Controller (INTC)
		setPreComment​(toAddr(0xFFFFED00), "Interrupt Priority Registers");
		createWordRegister(0xFFFFED00, "IPRA", "");
		createWordRegister(0xFFFFED04, "IPRC", "");
		createWordRegister(0xFFFFED06, "IPRD", "");
		createWordRegister(0xFFFFED08, "IPRE", "");
		createWordRegister(0xFFFFED0A, "IPRF", "");
		createWordRegister(0xFFFFED0C, "IPRG", "");
		createWordRegister(0xFFFFED0E, "IPRH", "");
		createWordRegister(0xFFFFED10, "IPRI", "");
		createWordRegister(0xFFFFED12, "IPRJ", "");
		createWordRegister(0xFFFFED14, "IPRK", "");
		createWordRegister(0xFFFFED16, "IPRL", "");
		createWordRegister(0xFFFFED18, "ICR", "");
		createWordRegister(0xFFFFED1A, "ISR", "");

		// User Break Controller (UBC)
		createWordRegister(0xFFFFEC00, "UBARH", "");
		createWordRegister(0xFFFFEC02, "UBARL", "");
		createWordRegister(0xFFFFEC04, "UBAMRH", "");
		createWordRegister(0xFFFFEC06, "UBAMRL", "");
		createWordRegister(0xFFFFEC08, "UBBR", "");
		createWordRegister(0xFFFFEC0A, "UBCE", "");

		// Direct Memory Access Controller (DMAC)
		createDWordRegister(0xFFFFECB0, "DMAOR", "DMA operation register");
		createDWordRegister(0xFFFFECC0, "SAR0", "DMA source address register");
		createDWordRegister(0xFFFFECC4, "DAR0", "DMA destination address register");
		createDWordRegister(0xFFFFECC8, "DMATCR0", "DMA transfer count register");
		createDWordRegister(0xFFFFECCC, "CHCR0", "DMA channel control register");
		createDWordRegister(0xFFFFECD0, "SAR1", "");
		createDWordRegister(0xFFFFECD4, "DAR1", "");
		createDWordRegister(0xFFFFECD8, "DMATCR1", "");
		createDWordRegister(0xFFFFECDC, "CHCR1", "");
		createDWordRegister(0xFFFFECE0, "SAR2", "");
		createDWordRegister(0xFFFFECE4, "DAR2", "");
		createDWordRegister(0xFFFFECE8, "DMATCR2", "");
		createDWordRegister(0xFFFFECEC, "CHCR2", "");
		createDWordRegister(0xFFFFECF0, "SAR3", "");
		createDWordRegister(0xFFFFECF4, "DAR3", "");
		createDWordRegister(0xFFFFECF8, "DMATCR3", "");
		createDWordRegister(0xFFFFECFC, "CHCR3", "");

		// Advanced Timer Unit-II (ATU-II)
		// Channel 0
		createByteRegister(0xFFFFF401, "TSTR1", "Timer start register 1");
		createByteRegister(0xFFFFF400, "TSTR2", "");
		createByteRegister(0xFFFFF402, "TSTR3", "");
		createByteRegister(0xFFFFF404, "PSCR1", "Prescaler register 1");
		createByteRegister(0xFFFFF406, "PSCR2", "");
		createByteRegister(0xFFFFF408, "PSCR3", "");
		createByteRegister(0xFFFFF40A, "PSCR4", "");
		createWordRegister(0xFFFFF430, "TCNT0H", "Free-running counter 0H");
		createWordRegister(0xFFFFF432, "TCNT0L", "");
		createWordRegister(0xFFFFF434, "ICR0AH", "Input capture register 0AH");
		createWordRegister(0xFFFFF436, "ICR0AL", "Input capture register 0AL");
		createWordRegister(0xFFFFF438, "ICR0BH", "");
		createWordRegister(0xFFFFF43A, "ICR0BL", "");
		createWordRegister(0xFFFFF43C, "ICR0CH", "");
		createWordRegister(0xFFFFF43E, "ICR0CL", "");
		createWordRegister(0xFFFFF420, "ICR0DH", "");
		createWordRegister(0xFFFFF422, "ICR0DL", "");
		createByteRegister(0xFFFFF424, "ITVRR1", "Timer interval interrupt request register 1");
		createByteRegister(0xFFFFF426, "ITVRR2A", "Timer interval interrupt request register 2A");
		createByteRegister(0xFFFFF428, "ITVRR2B", "");
		createByteRegister(0xFFFFF42A, "TIOR0", "Timer I/O control register");
		createWordRegister(0xFFFFF42C, "TSR0", "Timer status register 0");
		createWordRegister(0xFFFFF42E, "TIER0", "Timer interrupt enable register 0");
		// Channel 1
		createWordRegister(0xFFFFF440, "TCNT1A", "Free-running counter 1A");
		createWordRegister(0xFFFFF442, "TCNT1B", "");
		createWordRegister(0xFFFFF444, "GR1A", "General register 1A");
		createWordRegister(0xFFFFF446, "GR1B", "");
		createWordRegister(0xFFFFF448, "GR1C", "");
		createWordRegister(0xFFFFF44A, "GR1D", "");
		createWordRegister(0xFFFFF44C, "GR1E", "");
		createWordRegister(0xFFFFF44E, "GR1F", "");
		createWordRegister(0xFFFFF450, "GR1G", "");
		createWordRegister(0xFFFFF452, "GR1H", "");
		createWordRegister(0xFFFFF454, "OCR1", "Output compare register 1");
		createWordRegister(0xFFFFF456, "OSBR1", "Offset base register 1");
		createByteRegister(0xFFFFF459, "TIOR1A", "Timer I/O control register 1A");
		createByteRegister(0xFFFFF458, "TIOR1B", "");
		createByteRegister(0xFFFFF45B, "TIOR1C", "");
		createByteRegister(0xFFFFF45A, "TIOR1D", "");
		createByteRegister(0xFFFFF45D, "TCR1A", "Timer control register 1A");
		createByteRegister(0xFFFFF45C, "TCR1B", "");
		createWordRegister(0xFFFFF45E, "TSR1A", "Timer status register 1A");
		createWordRegister(0xFFFFF460, "TSR1B", "");
		createWordRegister(0xFFFFF462, "TIER1A", "");
		createWordRegister(0xFFFFF464, "TIER1B", "");
		createByteRegister(0xFFFFF466, "TRGMDR", "Trigger mode register");
		// Channel 2
		createWordRegister(0xFFFFF600, "TCNT2A", "");
		createWordRegister(0xFFFFF602, "TCNT2B", "");
		createWordRegister(0xFFFFF604, "GR2A", "");
		createWordRegister(0xFFFFF606, "GR2B", "");
		createWordRegister(0xFFFFF608, "GR2C", "");
		createWordRegister(0xFFFFF60A, "GR2D", "");
		createWordRegister(0xFFFFF60C, "GR2E", "");
		createWordRegister(0xFFFFF60E, "GR2F", "");
		createWordRegister(0xFFFFF610, "GR2G", "");
		createWordRegister(0xFFFFF612, "GR2H", "");
		createWordRegister(0xFFFFF614, "OCR2A", "");
		createWordRegister(0xFFFFF616, "OCR2B", "");
		createWordRegister(0xFFFFF618, "OCR2C", "");
		createWordRegister(0xFFFFF61A, "OCR2D", "");
		createWordRegister(0xFFFFF61C, "OCR2E", "");
		createWordRegister(0xFFFFF61E, "OCR2F", "");
		createWordRegister(0xFFFFF620, "OCR2G", "");
		createWordRegister(0xFFFFF622, "OCR2H", "");
		createWordRegister(0xFFFFF624, "OSBR2", "");
		createByteRegister(0xFFFFF627, "TIOR2A", "");
		createByteRegister(0xFFFFF626, "TIOR2B", "");
		createByteRegister(0xFFFFF629, "TIOR2C", "");
		createByteRegister(0xFFFFF628, "TIOR2D", "");
		createByteRegister(0xFFFFF62B, "TCR2A", "");
		createByteRegister(0xFFFFF62A, "TCR2B", "");
		createWordRegister(0xFFFFF62C, "TSR2A", "");
		createWordRegister(0xFFFFF62E, "TSR2B", "");
		createWordRegister(0xFFFFF630, "TIER2A", "");
		createWordRegister(0xFFFFF632, "TIER2B", "");
		// Channel 3-5
		createWordRegister(0xFFFFF480, "TSR3", "");
		createWordRegister(0xFFFFF482, "TIER3", "");
		createByteRegister(0xFFFFF484, "TMDR", "Timer mode register");
		// Channel 3
		createWordRegister(0xFFFFF4A0, "TCNT3", "");
		createWordRegister(0xFFFFF4A2, "GR3A", "");
		createWordRegister(0xFFFFF4A4, "GR3B", "");
		createWordRegister(0xFFFFF4A6, "GR3C", "");
		createWordRegister(0xFFFFF4A8, "GR3D", "");
		createByteRegister(0xFFFFF4AB, "TIOR3A", "");
		createByteRegister(0xFFFFF4AA, "TIOR3B", "");
		createByteRegister(0xFFFFF4AC, "TCR3", "");
		// Channel 4
		createWordRegister(0xFFFFF4C0, "TCNT4", "");
		createWordRegister(0xFFFFF4C2, "GR4A", "");
		createWordRegister(0xFFFFF4C4, "GR4B", "");
		createWordRegister(0xFFFFF4C6, "GR4C", "");
		createWordRegister(0xFFFFF4C8, "GR4D", "");
		createByteRegister(0xFFFFF4CB, "TIOR4A", "");
		createByteRegister(0xFFFFF4CA, "TIOR4B", "");
		createByteRegister(0xFFFFF4CC, "TCR4", "");
		// Channel 5
		createWordRegister(0xFFFFF4E0, "TCNT5", "");
		createWordRegister(0xFFFFF4E2, "GR5A", "");
		createWordRegister(0xFFFFF4E4, "GR5B", "");
		createWordRegister(0xFFFFF4E6, "GR5C", "");
		createWordRegister(0xFFFFF4E8, "GR5D", "");
		createByteRegister(0xFFFFF4EB, "TIOR5A", "");
		createByteRegister(0xFFFFF4EA, "TIOR5B", "");
		createByteRegister(0xFFFFF4EC, "TCR5", "");
		// Channel 6
		createWordRegister(0xFFFFF500, "TCNT6A", "");
		createWordRegister(0xFFFFF502, "TCNT6B", "");
		createWordRegister(0xFFFFF504, "TCNT6C", "");
		createWordRegister(0xFFFFF506, "TCNT6D", "");
		createWordRegister(0xFFFFF508, "CYLR6A", "Cycle register 6A");
		createWordRegister(0xFFFFF50A, "CYLR6B", "");
		createWordRegister(0xFFFFF50C, "CYLR6C", "");
		createWordRegister(0xFFFFF50E, "CYLR6D", "");
		createWordRegister(0xFFFFF510, "BFR6A", "Buffer register 6A");
		createWordRegister(0xFFFFF512, "BFR6B", "");
		createWordRegister(0xFFFFF514, "BFR6C", "");
		createWordRegister(0xFFFFF516, "BFR6D", "");
		createWordRegister(0xFFFFF518, "DTR6A", "Duty register 6A");
		createWordRegister(0xFFFFF51A, "DTR6B", "");
		createWordRegister(0xFFFFF51C, "DTR6C", "");
		createWordRegister(0xFFFFF51E, "DTR6D", "");
		createByteRegister(0xFFFFF521, "TCR6A", "");
		createByteRegister(0xFFFFF520, "TCR6B", "");
		createWordRegister(0xFFFFF522, "TSR6", "");
		createWordRegister(0xFFFFF524, "TIER6", "");
		createByteRegister(0xFFFFF526, "PMDR", "PWM mode register");
		// Channel 7
		createWordRegister(0xFFFFF580, "TCNT7A", "");
		createWordRegister(0xFFFFF582, "TCNT7B", "");
		createWordRegister(0xFFFFF584, "TCNT7C", "");
		createWordRegister(0xFFFFF586, "TCNT7D", "");
		createWordRegister(0xFFFFF588, "CYLR7A", "");
		createWordRegister(0xFFFFF58A, "CYLR7B", "");
		createWordRegister(0xFFFFF58C, "CYLR7C", "");
		createWordRegister(0xFFFFF58E, "CYLR7D", "");
		createWordRegister(0xFFFFF590, "BFR7A", "");
		createWordRegister(0xFFFFF592, "BFR7B", "");
		createWordRegister(0xFFFFF594, "BFR7C", "");
		createWordRegister(0xFFFFF596, "BFR7D", "");
		createWordRegister(0xFFFFF598, "DTR7A", "");
		createWordRegister(0xFFFFF59A, "DTR7B", "");
		createWordRegister(0xFFFFF59C, "DTR7C", "");
		createWordRegister(0xFFFFF59E, "DTR7D", "");
		createByteRegister(0xFFFFF5A1, "TCR7A", "");
		createByteRegister(0xFFFFF5A0, "TCR7B", "");
		createWordRegister(0xFFFFF5A2, "TSR7", "");
		createWordRegister(0xFFFFF5A4, "TIER7", "");
		// Channel 8
		createWordRegister(0xFFFFF640, "DCNT8A", "Down-counter 8A");
		createWordRegister(0xFFFFF642, "DCNT8B", "");
		createWordRegister(0xFFFFF644, "DCNT8C", "");
		createWordRegister(0xFFFFF646, "DCNT8D", "");
		createWordRegister(0xFFFFF648, "DCNT8E", "");
		createWordRegister(0xFFFFF64A, "DCNT8F", "");
		createWordRegister(0xFFFFF64C, "DCNT8G", "");
		createWordRegister(0xFFFFF64E, "DCNT8H", "");
		createWordRegister(0xFFFFF650, "DCNT8I", "");
		createWordRegister(0xFFFFF652, "DCNT8J", "");
		createWordRegister(0xFFFFF654, "DCNT8K", "");
		createWordRegister(0xFFFFF656, "DCNT8L", "");
		createWordRegister(0xFFFFF658, "DCNT8M", "");
		createWordRegister(0xFFFFF65A, "DCNT8N", "");
		createWordRegister(0xFFFFF65C, "DCNT8O", "");
		createWordRegister(0xFFFFF65E, "DCNT8P", "");
		createWordRegister(0xFFFFF660, "RLDR8", "Reload register 8");
		createWordRegister(0xFFFFF662, "TCNR", "Timer connection register");
		createWordRegister(0xFFFFF664, "OTR", "One-shot pulse terminate register");
		createWordRegister(0xFFFFF666, "DSTR", "Down-count start register");
		createByteRegister(0xFFFFF668, "TCR8", "");
		createWordRegister(0xFFFFF66A, "TSR8", "");
		createWordRegister(0xFFFFF66C, "TIER8", "");
		createByteRegister(0xFFFFF66E, "RLDENR", "Reload enable register");
		// Channel 9
		createByteRegister(0xFFFFF680, "ECNT9A", "Event counter 9A");
		createByteRegister(0xFFFFF682, "ECNT9B", "");
		createByteRegister(0xFFFFF684, "ECNT9C", "");
		createByteRegister(0xFFFFF686, "ECNT9D", "");
		createByteRegister(0xFFFFF688, "ECNT9E", "");
		createByteRegister(0xFFFFF68A, "ECNT9F", "");
		createByteRegister(0xFFFFF68C, "GR9A", "");
		createByteRegister(0xFFFFF68E, "GR9B", "");
		createByteRegister(0xFFFFF690, "GR9C", "");
		createByteRegister(0xFFFFF692, "GR9D", "");
		createByteRegister(0xFFFFF694, "GR9E", "");
		createByteRegister(0xFFFFF696, "GR9F", "");
		createByteRegister(0xFFFFF698, "TCR9A", "");
		createByteRegister(0xFFFFF69A, "TCR9B", "");
		createByteRegister(0xFFFFF69C, "TCR9C", "");
		createWordRegister(0xFFFFF69E, "TSR9", "");
		createWordRegister(0xFFFFF6A0, "TIER9", "");
		// Channel 10
		createWordRegister(0xFFFFF6C0, "TCNT10AH", "Free-running counter 10AH");
		createWordRegister(0xFFFFF6C2, "TCNT10AL", "Free-running counter 10AL");
		createByteRegister(0xFFFFF6C4, "TCNT10B", "Event counter 10B");
		createWordRegister(0xFFFFF6C6, "TCNT10C", "Reload counter 10C");
		createWordRegister(0xFFFFF6C8, "TCNT10D", "Correction counter 10D");
		createWordRegister(0xFFFFF6CA, "TCNT10E", "Correction angle counter 10E");
		createWordRegister(0xFFFFF6CC, "TCNT10F", "Correction angle counter 10F");
		createWordRegister(0xFFFFF6CE, "TCNT10G", "Free-running counter 10G");
		createWordRegister(0xFFFFF6D0, "ICR10AH", "Input capture register 10AH");
		createWordRegister(0xFFFFF6D2, "ICR10AL", "");
		createWordRegister(0xFFFFF6D4, "OCR10AH", "Output compare register 10AH");
		createWordRegister(0xFFFFF6D6, "OCR10AL", "");
		createByteRegister(0xFFFFF6D8, "OCR10B", "");
		createWordRegister(0xFFFFF6DA, "RLD10C", "");
		createWordRegister(0xFFFFF6DC, "GRG10G", "");
		createByteRegister(0xFFFFF6DE, "TCNT10H", "Noise canceler counter 10H");
		createByteRegister(0xFFFFF6E0, "NCR10", "Noise canceler register 10");
		createByteRegister(0xFFFFF6E2, "TIOR10", "");
		createByteRegister(0xFFFFF6E4, "TCR10", "");
		createWordRegister(0xFFFFF6E6, "TCCLR10", "Correction counter clear register 10");
		createWordRegister(0xFFFFF6E8, "TSR10", "");
		createWordRegister(0xFFFFF6EA, "TIER10", "");
		// Channel 11
		createWordRegister(0xFFFFF5C0, "TCNT11", "Free-running counter 11");
		createWordRegister(0xFFFFF5C2, "GR11A", "");
		createWordRegister(0xFFFFF5C4, "GR11B", "");
		createByteRegister(0xFFFFF5C6, "TIOR11", "");
		createByteRegister(0xFFFFF5C8, "TCR11", "");
		createWordRegister(0xFFFFF5CA, "TSR11", "");
		createWordRegister(0xFFFFF5CC, "TIER11", "");

		// Advanced Pulse Controller (APC)
		createWordRegister(0xFFFFF700, "POPCR", "Pulse output port control register");

		// Watchdog Timer (WDT)
		createByteRegister(0xFFFFEC10, "TCSR", "Timer control/status register");
		createByteRegister(0xFFFFEC11, "TCNT", "Timer counter");
		createByteRegister(0xFFFFEC12, "RSTCSR", "Reset control/status register Write");
		createByteRegister(0xFFFFEC13, "RSTCSRR", "Reset control/status register Read");

		// Compare Match Timer (CMT)
		createWordRegister(0xFFFFF710, "CMSTR", "Compare match timer start register");
		createWordRegister(0xFFFFF712, "CMCSR0", "Compare match timer control/status register 0");
		createWordRegister(0xFFFFF714, "CMCNT0", "Compare match timer counter 0");
		createWordRegister(0xFFFFF716, "CMCOR0", "Compare match timer constant register 0");
		createWordRegister(0xFFFFF718, "CMCSR1", "");
		createWordRegister(0xFFFFF71A, "CMCNT1", "");
		createWordRegister(0xFFFFF71C, "CMCOR1", "");

		// Serial Communication Interface (SCI)
		// Channel 0
		createByteRegister(0xFFFFF000, "SMR0", "Serial mode register");
		createByteRegister(0xFFFFF001, "BRR0", "Bit rate register");
		createByteRegister(0xFFFFF002, "SCR0", "Serial control register");
		createByteRegister(0xFFFFF003, "TDR0", "Transmit data register");
		createByteRegister(0xFFFFF004, "SSR0", "Serial status register");
		createByteRegister(0xFFFFF005, "RDR0", "Receive data register");
		createByteRegister(0xFFFFF006, "SDCR0", "Serial direction control register");
		// Channel 1
		createByteRegister(0xFFFFF008, "SMR1", "");
		createByteRegister(0xFFFFF009, "BRR1", "");
		createByteRegister(0xFFFFF00A, "SCR1", "");
		createByteRegister(0xFFFFF00B, "TDR1", "");
		createByteRegister(0xFFFFF00C, "SSR1", "");
		createByteRegister(0xFFFFF00D, "RDR1", "");
		createByteRegister(0xFFFFF00E, "SDCR1", "");
		// Channel 2
		createByteRegister(0xFFFFF010, "SMR2", "");
		createByteRegister(0xFFFFF011, "BRR2", "");
		createByteRegister(0xFFFFF012, "SCR2", "");
		createByteRegister(0xFFFFF013, "TDR2", "");
		createByteRegister(0xFFFFF014, "SSR2", "");
		createByteRegister(0xFFFFF015, "RDR2", "");
		createByteRegister(0xFFFFF016, "SDCR2", "");
		// Channel 3
		createByteRegister(0xFFFFF018, "SMR3", "");
		createByteRegister(0xFFFFF019, "BRR3", "");
		createByteRegister(0xFFFFF01A, "SCR3", "");
		createByteRegister(0xFFFFF01B, "TDR3", "");
		createByteRegister(0xFFFFF01C, "SSR3", "");
		createByteRegister(0xFFFFF01D, "RDR3", "");
		createByteRegister(0xFFFFF01E, "SDCR3", "");
		// Channel 4
		createByteRegister(0xFFFFF020, "SMR4", "");
		createByteRegister(0xFFFFF021, "BRR4", "");
		createByteRegister(0xFFFFF022, "SCR4", "");
		createByteRegister(0xFFFFF023, "TDR4", "");
		createByteRegister(0xFFFFF024, "SSR4", "");
		createByteRegister(0xFFFFF025, "RDR4", "");
		createByteRegister(0xFFFFF026, "SDCR4", "");

		// Hitachi Controller Area Network (HCAN)
		createByteRegister(0xFFFFE400, "MCR", "Master control register");
		createByteRegister(0xFFFFE401, "GSR", "General status register");
		createWordRegister(0xFFFFE402, "BCR", "Bit configuration register");
		createWordRegister(0xFFFFE404, "MBCR", "Mailbox configuration register");
		createWordRegister(0xFFFFE406, "TXPR", "Transmit wait register");
		createWordRegister(0xFFFFE408, "TXCR", "Transmit wait cancel register");
		createWordRegister(0xFFFFE40A, "TXACK", "Transmit acknowledge register");
		createWordRegister(0xFFFFE40C, "ABACK", "Abort acknowledge register");
		createWordRegister(0xFFFFE40E, "RXPR", "Receive complete register");
		createWordRegister(0xFFFFE410, "RFPR", "Remote request register");
		createWordRegister(0xFFFFE412, "IRR", "Interrupt register");
		createWordRegister(0xFFFFE414, "MBIMR", "Mailbox interrupt mask register");
		createWordRegister(0xFFFFE416, "IMR", "Interrupt mask register");
		createByteRegister(0xFFFFE418, "REC", "Receive error counter");
		createByteRegister(0xFFFFE419, "TEC", "Transmit error counter");
		createWordRegister(0xFFFFE41A, "UMSR", "Unread message status register");
		createWordRegister(0xFFFFE41C, "LAFML", "Local acceptance filter mask L");
		createWordRegister(0xFFFFE41E, "LAFMH", "Local acceptance filter mask H");

		// A/D Converter
		createWordRegister(0xFFFFF800, "ADDR0", "A/D data register 0");
		createWordRegister(0xFFFFF802, "ADDR1", "");
		createWordRegister(0xFFFFF804, "ADDR2", "");
		createWordRegister(0xFFFFF806, "ADDR3", "");
		createWordRegister(0xFFFFF808, "ADDR4", "");
		createWordRegister(0xFFFFF80A, "ADDR5", "");
		createWordRegister(0xFFFFF80C, "ADDR6", "");
		createWordRegister(0xFFFFF80E, "ADDR7", "");
		createWordRegister(0xFFFFF810, "ADDR8", "");
		createWordRegister(0xFFFFF812, "ADDR9", "");
		createWordRegister(0xFFFFF814, "ADDR10", "");
		createWordRegister(0xFFFFF816, "ADDR11", "");
		createWordRegister(0xFFFFF820, "ADDR12", "");
		createWordRegister(0xFFFFF822, "ADDR13", "");
		createWordRegister(0xFFFFF824, "ADDR14", "");
		createWordRegister(0xFFFFF826, "ADDR15", "");
		createByteRegister(0xFFFFF818, "ADCSR0", "A/D control/status register 0");
		createByteRegister(0xFFFFF819, "ADCR0", "A/D control register 0");
		createByteRegister(0xFFFFF76E, "ADTRGR0", "A/D trigger register 0");
		createByteRegister(0xFFFFF838, "ADCSR1", "");
		createByteRegister(0xFFFFF839, "ADCR1", "");
		createByteRegister(0xFFFFF858, "ADCSR2", "");
		createByteRegister(0xFFFFF859, "ADCR2", "");
		createByteRegister(0xFFFFF72E, "ADTRGR1", "");

		// Pin Function Controller (PFC)
		createWordRegister(0xFFFFF720, "PAIOR", "Port A IO register");
		createWordRegister(0xFFFFF722, "PACRH", "Port A control register H");
		createWordRegister(0xFFFFF724, "PACRL", "Port A control register L");
		createWordRegister(0xFFFFF730, "PBIOR", "");
		createWordRegister(0xFFFFF732, "PBCRH", "");
		createWordRegister(0xFFFFF734, "PBCRL", "");
		createWordRegister(0xFFFFF736, "PBIR", "Port B invert register");
		createWordRegister(0xFFFFF73A, "PCIOR", "");
		createWordRegister(0xFFFFF73C, "PCCR", "");
		createWordRegister(0xFFFFF740, "PDIOR", "");
		createWordRegister(0xFFFFF742, "PDCRH", "");
		createWordRegister(0xFFFFF744, "PDCRL", "");
		createWordRegister(0xFFFFF750, "PEIOR", "");
		createWordRegister(0xFFFFF752, "PECR", "");
		createWordRegister(0xFFFFF748, "PFIOR", "");
		createWordRegister(0xFFFFF74A, "PFCRH", "");
		createWordRegister(0xFFFFF74C, "PFCRL", "");
		createWordRegister(0xFFFFF760, "PGIOR", "");
		createWordRegister(0xFFFFF762, "PGCR", "");
		createWordRegister(0xFFFFF728, "PHIOR", "");
		createWordRegister(0xFFFFF72A, "PHCR", "");
		createWordRegister(0xFFFFF766, "PJIOR", "");
		createWordRegister(0xFFFFF768, "PJCRH", "");
		createWordRegister(0xFFFFF76A, "PJCRL", "");
		createWordRegister(0xFFFFF770, "PKIOR", "");
		createWordRegister(0xFFFFF772, "PKCRH", "");
		createWordRegister(0xFFFFF774, "PKCRL", "");
		createWordRegister(0xFFFFF776, "PKIR", "");

		// I/P Ports (I/O)
		createWordRegister(0xFFFFF726, "PADR", "Port A data register");
		createWordRegister(0xFFFFF738, "PBDR", "Port B data register");
		createWordRegister(0xFFFFF73E, "PCDR", "Port C data register");
		createWordRegister(0xFFFFF746, "PDDR", "Port D data register");
		createWordRegister(0xFFFFF754, "PEDR", "Port E data register");
		createWordRegister(0xFFFFF74E, "PFDR", "Port F data register");
		createWordRegister(0xFFFFF764, "PGDR", "Port G data register");
		createWordRegister(0xFFFFF72C, "PHDR", "Port H data register");
		createWordRegister(0xFFFFF76C, "PJDR", "Port J data register");
		createWordRegister(0xFFFFF778, "PKDR", "Port K data register");

		// ROM
		createByteRegister(0xFFFFE800, "FLMCR1", "Flash memory control register 1");
		createByteRegister(0xFFFFE801, "FLMCR2", "Flash memory control register 2");
		createByteRegister(0xFFFFE802, "EBR1", "Erase block register 1");
		createByteRegister(0xFFFFE803, "EBR2", "Erase block register 1");
		createWordRegister(0xFFFFEC20, "BCR1", "Bus control register 1");
		createWordRegister(0xFFFFEC22, "BCR2", "Bus control register 2");
		createWordRegister(0xFFFFEC24, "WCR", "Wait state control register");
		createWordRegister(0xFFFFEC26, "RAMER", "Ram emulation register");
		createByteRegister(0xFFFFEC14, "SBYCR", "Standby control register");
		createByteRegister(0xFFFFF708, "SYSCR", "System control register");
		createByteRegister(0xFFFFF70A, "MSTCR", "Module standby control register");

		createByteRegisterArray(0xFFFFE420, 0x08, "MC0", "Message control 0");
		createByteRegisterArray(0xFFFFE428, 0x08, "MC1", "Message control 1");
		createByteRegisterArray(0xFFFFE430, 0x08, "MC2", "Message control 2");
		createByteRegisterArray(0xFFFFE438, 0x08, "MC3", "Message control 3");
		createByteRegisterArray(0xFFFFE440, 0x08, "MC4", "Message control 4");
		createByteRegisterArray(0xFFFFE448, 0x08, "MC5", "Message control 5");
		createByteRegisterArray(0xFFFFE450, 0x08, "MC6", "Message control 6");
		createByteRegisterArray(0xFFFFE458, 0x08, "MC7", "Message control 7");
		createByteRegisterArray(0xFFFFE460, 0x08, "MC8", "Message control 8");
		createByteRegisterArray(0xFFFFE468, 0x08, "MC9", "Message control 9");
		createByteRegisterArray(0xFFFFE470, 0x08, "MC10", "Message control 10");
		createByteRegisterArray(0xFFFFE478, 0x08, "MC11", "Message control 11");
		createByteRegisterArray(0xFFFFE480, 0x08, "MC12", "Message control 12");
		createByteRegisterArray(0xFFFFE488, 0x08, "MC13", "Message control 13");
		createByteRegisterArray(0xFFFFE490, 0x08, "MC14", "Message control 14");
		createByteRegisterArray(0xFFFFE498, 0x08, "MC15", "Message control 15");
		createByteRegisterArray(0xFFFFE4B0, 0x08, "MD0", "Message data 0");
		createByteRegisterArray(0xFFFFE4B8, 0x08, "MD1", "Message data 1");
		createByteRegisterArray(0xFFFFE4C0, 0x08, "MD2", "Message data 2");
		createByteRegisterArray(0xFFFFE4C8, 0x08, "MD3", "Message data 3");
		createByteRegisterArray(0xFFFFE4D0, 0x08, "MD4", "Message data 4");
		createByteRegisterArray(0xFFFFE4D8, 0x08, "MD5", "Message data 5");
		createByteRegisterArray(0xFFFFE4E0, 0x08, "MD6", "Message data 6");
		createByteRegisterArray(0xFFFFE4E8, 0x08, "MD7", "Message data 7");
		createByteRegisterArray(0xFFFFE4F0, 0x08, "MD8", "Message data 8");
		createByteRegisterArray(0xFFFFE4F8, 0x08, "MD9", "Message data 9");
		createByteRegisterArray(0xFFFFE500, 0x08, "MD10", "Message data 10");
		createByteRegisterArray(0xFFFFE508, 0x08, "MD11", "Message data 11");
		createByteRegisterArray(0xFFFFE510, 0x08, "MD12", "Message data 12");
		createByteRegisterArray(0xFFFFE518, 0x08, "MD13", "Message data 13");
		createByteRegisterArray(0xFFFFE520, 0x08, "MD14", "Message data 14");
		createByteRegisterArray(0xFFFFE528, 0x08, "MD15", "Message data 15");

		return;
	}

	private void labelMUT(int address, String label, String comment) throws Exception {
		createLabel(toAddr(address), label, true);
		setPlateComment​(toAddr(address), comment);

		Data vector = getDataAt(toAddr(address));
		if (vector.isPointer()) {
			Address addr = (Address) vector.getValue();
			createLabel(addr, label, false);
			setPlateComment​(addr, comment);
		}
	}

	private void findMutTable() throws Exception {
		boolean forward = true;
		boolean tableFound = false;
		Address mutAddr = toAddr(0x00);
		CodeUnitIterator cuIter = currentProgram.getListing().getCodeUnits(toAddr(0x00), forward);
		while (cuIter.hasNext() && !monitor.isCancelled()) {
			CodeUnit cu = cuIter.next();

			if (cu instanceof Instruction) {
				Instruction instruction = (Instruction) cu;
				Address currentAddr = instruction.getMinAddress();

				if (!(instruction.getMnemonicString().contains("mov.w"))) {
					continue;
				}

				if (instruction.getNumOperands() != 2) {
					continue;
				}

				Object[] opObjects0 = instruction.getOpObjects(0);
				if (opObjects0.length != 2 || !(opObjects0[0] instanceof Scalar)
						|| !(opObjects0[1] instanceof Register)) {
					continue;
				}

				Object[] opObjects1 = instruction.getOpObjects(1);
				if (opObjects1.length != 1 || !(opObjects1[0] instanceof Register)) {
					continue;
				}

				Scalar scalar = (Scalar) opObjects0[0];

				byte[] bytey = getBytes(toAddr(scalar.toString()), 2);

				int number = bytey[1] & 0xff;
				if (number == 0xBF) {
					println("\t\tFound mov.w of 0xBF at: " + currentAddr.toString());

					CodeUnit nextInst = currentProgram.getListing().getCodeUnitAt(currentAddr.add(0x06));
					String mnemonic = nextInst.getMnemonicString();
					if (mnemonic.contains("shll2")) {
						println("\t\t\tFound shll2 at: " + nextInst.getMinAddress().toString());

						CodeUnit cuInst = currentProgram.getListing().getCodeUnitAt(currentAddr.add(0x08));
						Instruction mutInst = (Instruction) cuInst;
						Object[] opObjectsMut0 = mutInst.getOpObjects(0);

						if (opObjectsMut0.length != 2 || !(opObjectsMut0[0] instanceof Scalar)
								|| !(opObjectsMut0[1] instanceof Register)) {
							continue;
						}

						Scalar mutScalar = (Scalar) opObjectsMut0[0];
						println("\t\t\tPointer to MUT table address at: " + mutScalar.toString());

						Data data = getDataAt(toAddr(mutScalar.toString()));

						mutAddr = toAddr(data.getDefaultValueRepresentation());
						println("\t\tMut table is located at: " + mutAddr.toString());

						tableFound = true;
						break;

					}
				}
			}

		}

		if (tableFound) {
			Address currentAddress = toAddr(mutAddr.toString());
			Address tableEnd = toAddr(0x00);
			int counter = 0;
			while (true) {
				if (monitor.isCancelled()) {
					break;
				}
				try {
					Data data = createData​(currentAddress, new Pointer32DataType());
				} catch (CodeUnitInsertionException e) {
					// println("\t\tData already defined at:" + currentAddress.toString());
				}
				Data data = getDataAt(currentAddress);
				String label = "MUT_" + Integer.toHexString(counter);
				createLabel(currentAddress, label, true);
				if (data.isPointer()) {
					Address addr = (Address) data.getValue();
					if (addr.equals(toAddr(0xFFFFFFFF))) {
						tableEnd = currentAddress.add(-0x04);
						println("\t\tMut Table ends at: " + tableEnd.toString());
						break;
					}
					createLabel(addr, label, false);
				}

				currentAddress = currentAddress.add(0x04);
				counter = counter + 1;
			}
		} else {
			println("Could not locate the MUT Table");
		}
	}

	private void labelFunction(int address, String label, String comment) throws Exception {
		Function func = getFunctionAt(toAddr(address));

		if (func == null) {
			Function newFunc = createFunction​(toAddr(address), label);
			newFunc.setComment(comment);
		} else {
			func.setName(label, SourceType.ANALYSIS);
			func.setComment(comment);
		}

	}

	private void labelKnowFunctions() throws Exception {
		labelFunction(0xC28, "table_lookup_byte", "Look up the current BYTE value at the table stored at R4");
		labelFunction(0xE02, "table_lookup_word", "Look up the current WORD value at the table stored at R4");
		labelFunction(0xCC6, "axis_lookup", "Look up the current value in the axis stored at R4");
		labelFunction(0x400, "disable_interrupts", "Set interrupt mask of SR to 15, storing the old SR on the stack");
		labelFunction(0x41E, "enable_interrupts", "Restore the previous SR, pushed to the stack by disable_interrupts");
		labelFunction(0x430, "set_interrupt_mask",
				"Set a specific interrupt mask in SR. Takes a 4 bit number in R4 for the mask.");
		labelFunction(0x500, "add_capped", "Add R4 and R5, storing WORD result in R0, max 0xFFFF");
		labelFunction(0x514, "add_r4_and_r5", "Add R4 and R5, storing WORD result in R0");
		labelFunction(0x51C, "add_word_capped", "Add R4 and R5, storing WORD result in R0, max 0xFFFF");
		labelFunction(0x52C, "memclear", "Clear RAM between R4 and R5");
		labelFunction(0x53e, "decrement_block",
				"Subtract 1 from all words between R4 and R5. R4 is set to the next word after R5.");
		labelFunction(0x562, "increment_block",
				"Add 1 to all words between R4 and R5. R4 is set to the next word after R5.");
		labelFunction(0x590, "min_ff", "Set R0 the BYTE minimum of R4 and 0xFF");
		labelFunction(0x598, "min_ffff", "Set R0 the WORD minimum of R4 and 0xFFFF");
		labelFunction(0x5A8, "max_3_word", "Return the WORD maximum of R4, R5, R6 in R0");
		labelFunction(0x5B0, "max_3", "Return the maximum of R4, R5, R6 in R0");
		labelFunction(0x5D0, "r4_mult_r5_div_r6_capped_to_R0", "Lesser of ((R4*R5)/R6) and 0xFFFF -> R0");
		labelFunction(0x5E8, "r4_mult_r5_div_r6_to_R0",
				"Multiply R4 by R5, divide by R6 and return result in R0, capped at 0xFFFFFFFF");
		labelFunction(0x68A, "multR4R5divr6", "(((R4 * R5) / r6) + 1/2) -> R0");
		labelFunction(0x6A2, "sub_6A2", "(((R4 * R5) / r6) + 1/2) -> R0");
		labelFunction(0x752, "sub_752", "Lesser of [(R4 * R5) / 128] and 0xFFFF");
		labelFunction(0x762, "r0_is_r4_x_r5", "Lesser of ([(R4 * R5) / 128] + 1/2) and 0xFFFF -> R0");
		labelFunction(0x780, "r4xr5_strange",
				"Lesser of [(R4 * R5) / 128] and 0xFFFFFFFF -> R0, R5 is word length, R4 can be long word");
		labelFunction(0x7A6, "sub_7A6", "Lesser of [(R4 * R5) / 128] and 0xFFFFFFFF -> R0");
		labelFunction(0x7D0, "r4xr5", "Lesser of [(R4 * R5) / 256] and 0xFFFF -> R0");
		labelFunction(0x7E6, "sub_7E6", "Lesser of [(R4 * R5) / 256] and 0xFFFFFFFF -> R0");
		labelFunction(0x804, "r4_mult_r5_div_64_add_1_etc2_into_r0",
				"Lesser of ([(R4 * R5) / 256] +1/2) and 0xFFFF -> R0");
		labelFunction(0x864, "shlr8_byte", "(R4 / 256) -> R0");
		labelFunction(0x86A, "shlr16_word", "(R4 / 65536) -> R0");
		labelFunction(0x870, "shll8_byte", "(R4 * 256) -> R0");
		labelFunction(0x876, "shll16_word", "(R4 * 65536) -> R0");
		labelFunction(0x87C, "second_byte_plus_1", "Lesser of (MSB of R4) and (0xFF) -> R0");
		labelFunction(0x898, "second_word_plus_1", "Lesser of (MSW of R4) and (0xFFFF) -> R0");
		labelFunction(0x8B8, "NOT_SHLL8_OR_R4_INTO_R0", "inv(byte(R4))|byte(R4) -> R0 (word length value is result)");
		labelFunction(0x8C4, "R5_Div_R4_Into_R0", "min(R4 / R5, 0xFFFF) -> R0");
		labelFunction(0x902, "divide_long_by_word", "min(R4 / R5, 0xFFFF) -> R0");
		labelFunction(0x9B0, "divide_words", "min((R4 / R5) + 1/2), 0xFFFF) -> R0");
		labelFunction(0x9F2, "R4_DIV_R5_Into_R0_0", "min((R4 / R5) + 1/2, 0xFFFF) -> R0");
		labelFunction(0x9FA, "sub_9FA", "min((R4 / R5) + 1/2, 0xFFFF) -> R0");
		labelFunction(0xAB8, "R5x_R0minusR6_plusR6xR4", "min(((R4 * r6) + (R5 * (256 - r6))) / 256), 0xFFFF) -> R0");
		labelFunction(0xAE0, "sub_AE0", "min((R4 * r6) + (R5 * (256 - r6)) / 256, 0xFFFFFFFF) -> R0");
		labelFunction(0xB16, "BETWEEN_R4_R5byR6",
				"min((R4 * r6 + R5 * (255 - R6)) / 255, 0x????) -> R0. This is a sub to interpolate between R4 and R5 using r6");
		labelFunction(0xD7A, "sub_D7A", "Linear Interpolation of R4 and R5 using r6 as the scalar, results -> R0");
		labelFunction(0xDC6, "read_mapindex_byte", "Reads BYTE at (R4 + (MAPindex * 4)) into R0");
		labelFunction(0xDD2, "read_mapindex_word", "Reads WORD at (R4 + (MAPindex * 4)) into R0");
		labelFunction(0xDE0, "table_lookup_byte_mapindex",
				"Call table_lookup_byte with a table at (R4 + (MAPindex * 4))");
		labelFunction(0xDF6, "read_mapindex_long", "Reads DWORD at (R4 + (MAPindex * 4)) into R0");
		labelFunction(0xEA6, "table_lookup_word_mapindex",
				"Call table_lookup_word with a table at (R4 + (MAPindex * 4))");
		labelFunction(0xED8, "multiply_capped", "min(R4 * R5, 0xFFFF) -> R0");
		labelFunction(0xEEE, "multiply", "min(R4 * R5, 0xFFFF) -> R0");
		labelFunction(0xEF8, "multiply_word", "Lesser of R4*R5 and 0xFFFFFFFF -> R0");
		labelFunction(0xF0C, "subtract_nowrap_word", "(R4 > R5) ? (R4 - R5) : 0  -> R0");
		labelFunction(0xF12, "subtract_nowrap_byte", "max(R4 - R5, 0) -> R0");
	}

	private void sh2() throws Exception {
		println("Running Mitsubishi SuperH ECU Analysis");

		String rom_id = getRomID(0xF52, "ROM_ID");
		println("\tROM ID is: " + rom_id);

		try {
			println("\tCreating RAM segment at 0xFFFF600 with length 0x8000");
			createMemoryBlock​("data", toAddr(0xFFFF6000), null, 0x8000, false);
		} catch (MemoryConflictException e) {
			println("\t\tRAM segment at 0xFFFF600 already exists");
		}

		try {
			println("\tCreating Hardware register segment at 0xFFFFE400 with length 0x1460");
			createMemoryBlock​("reg", toAddr(0xFFFFE400), null, 0x1460, false);
		} catch (MemoryConflictException e) {
			println("\t\tHardware Register segment at 0xFFFFE400 already exists");
		}

		println("\tLabelling Hardware registers");
		sh2LabelRegisters();

		println("\tCreating vector table");
		createVectorTable(0x100);

		println("\tCreating data structures");
		createStructures();

		println("\tFixing constant variables");
		fixConstants();

		println("\tStarting Auto Analysis");
		analyzeAll(currentProgram);

		println("\tFinding MUT Table");
		findMutTable();

		println("\tLabelling known functions");
		labelKnowFunctions();

		return;
	}

	@Override
	public void run() throws Exception {
		println("Mitsubishi ECU Auto Analysis Tool for Ghidra");

		println("Checking selected processor");
		Processor sh2 = Processor.toProcessor("SuperH");

		Program program = currentProgram;
		Language lang = program.getLanguage();
		Processor proc = lang.getProcessor();

		if (proc.compareTo(sh2) == 0) {
			println("\tProcessor is SuperH");
			sh2();
		} else {
			println("\tProcessor not supported!");
		}

		return;
	}

}