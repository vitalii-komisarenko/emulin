package engine;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

import engine.Memory;

public class Elf {
	public EIdent e_ident;
	public short e_type;
	public short e_machine;
	public int e_version;
	public long e_entry;
	public long e_phoff;
	public long e_shoff;
	public int e_flags;
	public short e_ehsize;
	public short e_phentsize;
	public short e_phnum;
	public short e_shentsize;
	public short e_shnum;
	public short e_shstrndx;

	class EIdent {
		public byte EI_MAG0;
		public byte EI_MAG1;
		public byte EI_MAG2;
		public byte EI_MAG3;
		public byte EI_CLASS;
		public byte EI_DATA;
		public byte EI_VERSION;
		public byte EI_OSABI;
		public byte EI_ABIVERSION;
		public EIdent(byte[] bytes) {
			ByteBuffer buffer = ByteBuffer.wrap(bytes);
			EI_MAG0 = buffer.get();
			EI_MAG1 = buffer.get();
			EI_MAG2 = buffer.get();
			EI_MAG3 = buffer.get();
			EI_CLASS = buffer.get();
			EI_DATA = buffer.get();
			EI_VERSION = buffer.get();
			EI_OSABI = buffer.get();
			EI_ABIVERSION = buffer.get();

			if (EI_MAG0 != 0x7F) {
				throw new RuntimeException("EI_MAG0");
			}
			if (EI_MAG1 != 0x45) {
				throw new RuntimeException("EI_MAG1");
			}
			if (EI_MAG2 != 0x4C) {
				throw new RuntimeException("EI_MAG2");
			}
			if (EI_MAG3 != 0x46) {
				throw new RuntimeException("EI_MAG3");
			}
			if (EI_CLASS != 0x02) {
				throw new RuntimeException("Only 64 bit supported");
			}
			if (EI_DATA != 0x01) {
				throw new RuntimeException("Only little endian supported");
			}
			if (EI_VERSION != 0x01) {
				throw new RuntimeException("EI_VERSION");
			}
		}
	}

	class ProgramHeaderEntry {
		public int p_type;
		public int p_flags;
		public long p_offset;
		public long p_vaddr;
		public long p_paddr;
		public long p_filesz;
		public long p_memsz;
		public long p_align;

		public Elf parentElf;

		public ProgramHeaderEntry(byte[] bytes, Elf parent_elf) {
			parentElf = parent_elf;
			ByteBuffer buffer = ByteBuffer.wrap(bytes);
			buffer.order(ByteOrder.LITTLE_ENDIAN);
			p_type = buffer.getInt();
			p_flags = buffer.getInt();
			p_offset = buffer.getLong();
			p_vaddr = buffer.getLong();
			p_paddr = buffer.getLong();
			p_filesz = buffer.getLong();
			p_memsz = buffer.getLong();
			p_align = buffer.getLong();
		}

		public byte[] getBytes() {
			byte[] output = new byte[(int)p_memsz];
			byte[] dataInFile = parentElf.getElfBytes((int)p_offset, (int)p_filesz);

			for (int i=0; i<output.length; i++) {
				output[i] = (i < dataInFile.length) ? dataInFile[i] : 0;
			}
			
			return output;
		}
	}

	public ProgramHeaderEntry[] programHeaderEntries;

	public byte[] bytes;
	public byte[] getElfBytes(int pos, int length) {
		return Arrays.copyOfRange(bytes, pos, pos + length);
	}

	public Elf(byte[] _bytes) {
		bytes = _bytes.clone();
		e_ident = new EIdent(Arrays.copyOfRange(bytes, 0, 0x10));

		ByteBuffer buffer = ByteBuffer.wrap(Arrays.copyOfRange(bytes, 0x10, 0x40));
		buffer.order(ByteOrder.LITTLE_ENDIAN);

		e_type = buffer.getShort();
		e_machine = buffer.getShort();
		e_version = buffer.getInt();
		e_entry = buffer.getLong();
		e_phoff = buffer.getLong();
		e_shoff = buffer.getLong();
		e_flags = buffer.getInt();
		e_ehsize = buffer.getShort();
		e_phentsize = buffer.getShort();
		e_phnum = buffer.getShort();
		e_shentsize = buffer.getShort();
		e_shnum = buffer.getShort();
		e_shstrndx = buffer.getShort();

		if (e_version != 0x01) {
			throw new RuntimeException("e_version");
		}

		programHeaderEntries = new ProgramHeaderEntry[e_phnum];
		for (int i=0; i<e_phnum; i++) {
			byte[] phe_buffer = Arrays.copyOfRange(bytes, (int)e_phoff+i*e_phentsize, (int)e_phoff+(i+1)*e_phentsize);
			programHeaderEntries[i] = new ProgramHeaderEntry(phe_buffer, this);
		}
	}
	
	public void loadToMemory(Memory mem) {
		for (ProgramHeaderEntry ph: programHeaderEntries) {
			if (ph.p_type != 1) { // PT_LOAD
				continue;
			}
			if ((ph.p_flags & 0xfff00000) != 0) { // PF_MASKOS | PF_MASKPROC
				throw new RuntimeException("PF_MASKOS | PF_MASKPROC: " + ph.p_flags);
			}
			mem.writeBufferForce(ph.p_vaddr, (int)ph.p_memsz, ph.getBytes(),
				(ph.p_flags & 0x4) != 0, // PF_R
				(ph.p_flags & 0x2) != 0, // PF_W
				(ph.p_flags & 0x1) != 0  // PF_X
			);
		}
	}
}