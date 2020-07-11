interface Memory {
	/*
	 * Methods that check access rights
	 */
	 
	byte readByte(long pos);
	byte readByteExec(long pos);
	void writeByte(long pos, byte value);

	byte[] readBuffer(long pos, int size);
	void writeBuffer(long pos, int size, byte[] value);

	/*
	 * Methods that do not check access rights
	 */

	byte readByteForce(long pos);
	byte readByteExecForce(long pos);
	void writeByteForce(long pos, byte value, boolean readable, boolean writable, boolean executable);

	byte[] readBufferForce(long pos, int size);
	void writeBufferForce(long pos, int size, byte[] value);
	
	/*
	 * Methods to check access rights
	 */
	 
	boolean isReadable(long addr);
	boolean isWritable(long addr);
	boolean isExecutable(long addr);

	boolean isReadable(long addr, int size);
	boolean isWritable(long addr, int size);
	boolean isExecutable(long addr, int size);
}