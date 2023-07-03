import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.RandomAccessFile;
import java.io.Writer;


public class AllenBradlyCRC32Generator {

	private static String inFName = "";
	private static String outFName = "";
	private static int crcTableStart = 0;
	private static Boolean crcTableIdxFlag = false;
	private static Boolean littleEndian = true;

	public static byte[] readFileBuffer(RandomAccessFile f, int off, int len) {
		byte[] b = null;
		try {
			f.seek(off);
			b = new byte[len];
			f.read(b,0, len);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return b;
	}
	

	public static RandomAccessFile  openFile(String fileName) {
		RandomAccessFile f = null;
		try {
			f = new RandomAccessFile(fileName, "r");
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return f;
	}

	public static void closeFile(RandomAccessFile f) {
		try {
			if (f != null) {
				f.close();
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	public static void closeOutFile(Writer writer) {
		try {
			writer.close();
		} catch (Exception ex) {
			
		}
		
	}
	public static Writer openOutFile(String fName) {
		Writer writer=null;
		try {
			File file = new File(fName);
			if (!file.exists()) { 
				file.createNewFile();
			}
			
			writer = new OutputStreamWriter(new FileOutputStream(fName));
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return writer;
	}
	public static void writeFile(String fileName, byte[] data) {
		BufferedOutputStream bs = null;

		try {

		    FileOutputStream fs = new FileOutputStream(new File(fileName));
		    bs = new BufferedOutputStream(fs);
		    bs.write(data);
		    bs.close();
		    bs = null;

		} catch (Exception e) {
		    e.printStackTrace();
		}

		if (bs != null) try { bs.close(); } catch (Exception e) {}
    }

	public static byte[] getPadBuff (byte[] buffer, RandomAccessFile file) {
		byte[] retBuff = null;
		int blockOffset = 20;
		try {
			int blockSize = (((buffer[blockOffset+3]&0xFF) << 24) | 
					  ((buffer[blockOffset+2]&0xFF) << 16) |
					  ((buffer[blockOffset+1]&0xFF) <<  8) |
					  ((buffer[blockOffset+0]&0xFF) <<  0));

			int size = (int) (blockSize - file.length());
			retBuff = new byte[size];
			for (int i = -1;++i < size;) {
				retBuff[i] = (byte) 0xFF;
			}
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return retBuff;
	}
	public static int[] getCRCTable(byte[] buffer, int startIdx) {
		int[] retBuff = new int[256];
		int offset = startIdx;
		for (int i=-1; ++i < 256; offset += 4) {
			
			retBuff[i] = (((buffer[offset+3]&0xFF) << 24) | 
						  ((buffer[offset+2]&0xFF) << 16) |
						  ((buffer[offset+1]&0xFF) <<  8) |
						  ((buffer[offset+0]&0xFF) <<  0));
		}
		return retBuff;
	}
	public static int[] getCRCTable(byte[] buffer) {
		int startIdx;
		for (startIdx = -1; ++startIdx < buffer.length; ) {
			if(((buffer[startIdx+ 0]&0xFF) == 0x00) && 
			   ((buffer[startIdx+ 1]&0xFF) == 0x00) && 
			   ((buffer[startIdx+ 2]&0xFF) == 0x00) && 
			   ((buffer[startIdx+ 3]&0xFF) == 0x00) && 
			   
			   ((buffer[startIdx+ 4]&0xFF) == 0x96) && 
			   ((buffer[startIdx+ 5]&0xFF) == 0x30) && 
			   ((buffer[startIdx+ 6]&0xFF) == 0x07) && 
			   ((buffer[startIdx+ 7]&0xFF) == 0x77) &&
			   
			   ((buffer[startIdx+ 8]&0xFF) == 0x2C) && 
			   ((buffer[startIdx+ 9]&0xFF) == 0x61) && 
			   ((buffer[startIdx+10]&0xFF) == 0x0E) && 
			   ((buffer[startIdx+11]&0xFF) == 0xEE) &&
			   
			   ((buffer[startIdx+12]&0xFF) == 0xBA) && 
			   ((buffer[startIdx+13]&0xFF) == 0x51) && 
			   ((buffer[startIdx+14]&0xFF) == 0x09) && 
			   ((buffer[startIdx+15]&0xFF) == 0x99)) {
				
					return getCRCTable(buffer, startIdx);
			}
		}
		return null;
	}
	public static long update_crc (long crc, byte[] buffer, int length, int[] crcTable) {
		
		for (int i=-1; ++i < length;) {
			long buffer_L = buffer[i] & 0x0FFL;
			crc = (crcTable[ (int)((crc ^ (buffer_L & 0x0FF)) & 0xFFL)]  ^ (crc >> 8)) & 0x0FFFFFFFFL;
		}
		return crc;
	}
	public static void updateFileCRC(byte[] buffer, int crc) {
		byte b0 = 0;
		byte b1 = 0;
		byte b2 = 0;
		byte b3 = 0;
		if (littleEndian) {
			b3 = (byte) ((crc >> 24) & 0x0FF);
			b2 = (byte) ((crc >> 16) & 0x0FF);
			b1 = (byte) ((crc >>  8) & 0x0FF);
			b0 = (byte) ((crc >>  0) & 0x0FF);		
		} else {
			b0 = (byte) ((crc >> 24) & 0x0FF);
			b1 = (byte) ((crc >> 16) & 0x0FF);
			b2 = (byte) ((crc >>  8) & 0x0FF);
			b3 = (byte) ((crc >>  0) & 0x0FF);
		}
		int len = buffer.length;
		buffer[len - 8] = b0;
		buffer[len - 7] = b1;
		buffer[len - 6] = b2;
		buffer[len - 5] = b3;	
	}
	public static boolean processArgs(String [] args) {
		int len = args.length;

		for (int i=0; i < len;) {
			String option =  args[i];
			if (option.equalsIgnoreCase("-o")) {
				outFName = args[i+1];
				i += 2;			
			} else if (option.equalsIgnoreCase("-f")) {
				inFName = args[i+1];
				i += 2;	
			} else if (option.equalsIgnoreCase("-tidx")) {
				crcTableIdxFlag = true;
				crcTableStart = Integer.parseInt(args[i+1]);
				i += 2;	
			} else {
				return false;
			}
		}
		return true;
	}
	public static void showUsage() {
		System.out.println("Usage:\n");
		System.out.println("-f <input filename>		: input file name          : Required\n");
		System.out.println("-o <output filename>	: output file name         : Optional\n");
		System.out.println("-tidx					: crc poly table location  : Optional\n");

	}
	public static void main(String[] args){
		long CRC_INIT = 0x0FFFFFFFFL;
		long XO_ROT = 0x0FFFFFFFFL;

		
		RandomAccessFile file = null;
		Writer writer = null;

		try {
			Boolean procArgs = processArgs(args); 
			if (!procArgs || (inFName == null || inFName.equalsIgnoreCase(""))) {
				showUsage();				
			} else {

				//String inFName = "C:/Users/ajr117/Desktop/Package/1756-L61_20.58/PN-433399.bin";
				//String inFName = "C:/Users/ajr117/Desktop/Package/L64.v19.11.16/PN-85386.bin";
				//String inFName = "C:/Users/ajr117/Desktop/Package/L64.v20.12.79/PN-156388.bin";
				//String inFName = "C:/Users/ajr117/Desktop/Package/L64.v20.14.83/PN-274932.bin";
				//String inFName = "C:/Users/ajr117/Desktop/Package/L64.v20.14.83/PN-274932.bin";
				//String inFName = "C:/Users/ajr117/Desktop/Package/L64.v20.18.91/PN-337140.bin";
				//String inFName = "C:/Users/ajr117/Desktop/Package/OF8.v1.5/99223704.bin";
				file = openFile(inFName);
				int fileLen = (int) file.length();
				byte[] buffer = readFileBuffer(file, 0, (int)file.length());
				
				
				//
				// Determine the Pad length
				//
				byte[] padBuffer = getPadBuff(buffer, file);
				
				int[] crcTable = null;
				if (crcTableIdxFlag) {
					crcTable = getCRCTable(buffer, crcTableStart);
				} else {
					crcTable = getCRCTable(buffer);
				}
		
		
				//
				// CRC the file
				//
				Long crc = CRC_INIT;
				crc =  update_crc (crc, buffer, buffer.length-8,crcTable);
	
				//
				// CRC The padTable
				//
				crc =  update_crc (crc, padBuffer, padBuffer.length,crcTable);
				//
				// 9bf3640d
				//
				int crcValue = (((buffer[fileLen-8+3]&0x0FF) << 24) | 
						((buffer[fileLen-8+2]&0x0FF) << 16) |
						((buffer[fileLen-8+1]&0x0FF) <<  8) |
						((buffer[fileLen-8+0]&0x0FF) <<  0));
				
				if (outFName != null && !outFName.equalsIgnoreCase("")) {

					updateFileCRC(buffer, crc.intValue());
					writeFile(outFName, buffer);
				}

				System.out.println("The new CRC is : " + Integer.toHexString(crc.intValue()));
			}

			
		} catch (Exception ex) {
				ex.printStackTrace();
		} finally {
			closeOutFile(writer);
			closeFile(file);
		}
	}
}
