import java.util.stream.IntStream;

class MemoryImpl implements Memory {
	private class Byte {
		private byte value;
		private byte access_rights;
		private static final byte r = 0x01;
		private static final byte w = 0x02;
		private static final byte e = 0x04;
		public boolean isReadable()   { return (access_rights & r) != 0; }
		public boolean isWritable()   { return (access_rights & w) != 0; }
		public boolean isExecutable() { return (access_rights & e) != 0; }
		public void setReadable  (boolean new_value) { access_rights &= (w|e); access_rights |= new_value ? r : 0; }
		public void setWritable  (boolean new_value) { access_rights &= (r|e); access_rights |= new_value ? w : 0; }
		public void setExecutable(boolean new_value) { access_rights &= (r|w); access_rights |= new_value ? e : 0; }
		public byte read() { return value; }
		public void write(byte v) { value = v; }
	};
	
	private java.util.TreeMap<Long, Byte> map = new java.util.TreeMap<Long, Byte>();

	/*
	 * Methods that check access rights
	 */
	 
	public Byte getExistingByte(long pos) {
		if (!map.containsKey(pos)) {
			throw new RuntimeException();
		}
		return map.get(pos);
	}
	
	public byte readByte(long pos) {
		Byte b = getExistingByte(pos);
		if (!b.isReadable()) {
			throw new RuntimeException();
		}
		return b.read();
	}
	
	public byte readByteExec(long pos) {
		Byte b = getExistingByte(pos);
		if (!b.isExecutable()) {
			throw new RuntimeException();
		}
		return b.read();
	}
	
	public void writeByte(long pos, byte value) {
		Byte b = getExistingByte(pos);
		if (!b.isWritable()) {
			throw new RuntimeException();
		}
		b.write(value);
	}

	public byte[] readBuffer(long pos, int size) {
		byte[] buffer = new byte[size];
		for(int i=0; i<size; i++) {
			buffer[i] = readByte(pos + i);
		}
		return buffer;
	}
	
	public void writeBuffer(long pos, int size, byte[] value) {
		for (int i=0; i<size; i++) {
			writeByte(pos + i, value[i]);
		}
	}

	/*
	 * Methods that do not check access rights
	 */

	public byte readByteForce(long pos) {
		if (!map.containsKey(pos)) {
			throw new RuntimeException();
		}
		return map.get(pos).read();
	}
	
	public byte readByteExecForce(long pos) {
		return readByteForce(pos);
	}
	
	public void writeByteForce(long pos, byte value, boolean readable, boolean writable, boolean executable) {
		Byte b = new Byte();
		b.write(value);
		b.setReadable(readable);
		b.setWritable(writable);
		b.setExecutable(executable);
		if (map.containsKey(pos)) {
			throw new RuntimeException();
		}
		map.put(pos, b);
	}

	public byte[] readBufferForce(long pos, int size) {
		byte[] buffer = new byte[size];
		for(int i=0; i<size; i++) {
			buffer[i] = readByteForce(pos + i);
		}
		return buffer;		
	}

	public void writeBufferForce(long pos, int size, byte[] value, boolean readable, boolean writable, boolean executable) {
		for (int i=0; i<size; i++) {
			writeByteForce(pos + i, value[i], readable, writable, executable);
		}
	}
	
	/*
	 * Methods to check access rights
	 */
	 
	public boolean isReadable(long addr) {
		return getExistingByte(addr).isReadable();
	}
	
	public boolean isWritable(long addr) {
		return getExistingByte(addr).isWritable();
	}
	
	public boolean isExecutable(long addr) {
		return getExistingByte(addr).isExecutable();		
	}

	public boolean isReadable(long addr, int size) {
		IntStream stream = IntStream.range(0, size);
		return stream.allMatch(i -> isReadable(addr + i));
	}
	
	public boolean isWritable(long addr, int size) {
		IntStream stream = IntStream.range(0, size);
		return stream.allMatch(i -> isWritable(addr + i));
	}

	public boolean isExecutable(long addr, int size) {
		IntStream stream = IntStream.range(0, size);
		return stream.allMatch(i -> isExecutable(addr + i));
	}		
}