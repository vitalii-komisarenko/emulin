interface Memory {
	/*
	 * Methods that check access rights
	 */
	 
	public byte readByte(long pos);
	public byte readByteExec(long pos);
	public void writeByte(long pos, byte value);

	public byte[] readBuffer(long pos, int size);
	public void writeBuffer(long pos, int size, byte[] value);

	/*
	 * Methods that do not check access rights
	 */

	public byte readByteForce(long pos);
	public byte readByteExecForce(long pos);
	public void writeByteForce(long pos, byte value, boolean readable, boolean writable, boolean executable);

	public byte[] readBufferForce(long pos, int size);
	public void writeBufferForce(long pos, int size, byte[] value, boolean readable, boolean writable, boolean executable);
	
	/*
	 * Methods to check access rights
	 */
	 
	public boolean isReadable(long addr);
	public boolean isWritable(long addr);
	public boolean isExecutable(long addr);

	public boolean isReadable(long addr, int size);
	public boolean isWritable(long addr, int size);
	public boolean isExecutable(long addr, int size);
}