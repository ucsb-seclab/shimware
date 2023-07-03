
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.RandomAccessFile;
import java.io.Writer;
import java.util.zip.Adler32;
import java.util.zip.Checksum;


public class AllenBradlyCkSumGenerator {
	private static int totalUpper = 0;
	private static Long sumUpper = 0L;
	private static int totalLower = 0;
	private static Long sumLower = 0L;
	private static Long tempVal = 0L;
	private static Boolean littleEndian = false;

	private static String inFName = "";
	private static String outFName = "";
	private static boolean ctrlModule = false;
	private static boolean of8Module = false;
	private static boolean ewebModule = false;


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

	public static Integer getSimpleSum16(byte[] buffer, int start, int end) {
		//
		// Appears to be used in the OF8 checksum calculator
		//
		int total = 0;
		Long sum = 0L;

		for (int i = start; i < end; i+=2) {	
			if (littleEndian) {
				sum += (((buffer[i+1]&0xFF) <<  8) | 
						((buffer[i+0]&0xFF) <<  0));
				total = (int) (sum & 0x0FFFFFFFFL);
			} else {
				sum += (((buffer[i+0]&0xFF) <<  8) | 
						((buffer[i+1]&0xFF) <<  0));
				total = (int) (sum & 0x0FFFFFFFFL);
			}
		}
		return total;
	}
	public static Long generateCheckSum(Long sumUpper, Long sumLower ) {
		//
		// See what number to add to get back to the 12345678
		//
		Long startTime = System.currentTimeMillis();
		Long checkSumVal = 0L;
		int testVal = 0;
		int totalUpper = 0;
		int totalLower = 0;

		for (; checkSumVal <= 0x0FFFFFFFFL; checkSumVal++) {
			totalUpper = (int) ((sumUpper + checkSumVal) & 0x0FFFFFFFFL);
			totalLower = (int) ((sumLower + checkSumVal+1) & 0x0FFFFFFFFL);
			
			testVal = (int) ((totalUpper&0x0FFFF0000L) + (totalLower&0x0FFFF));
			if (testVal == 0x12345678) {
				System.out.println("checksum found value is: " + Integer.toHexString(checkSumVal.intValue()));
				break;
			}				
		}
		return checkSumVal;
	}
	
	public static Integer computeCheckSum(byte[] buffer, int length) {
		int retVal = 0;
		
		//
		// Determine what the checksum should be 
		//
		totalUpper = 0;
		sumUpper = 0L;
		totalLower = 0;
		sumLower = 0L;
		tempVal = 0L;
		for (int i = 0; i < length; i+=4) {				
			if (littleEndian) {
				tempVal = (long) (((buffer[i+3]&0xFF) << 24) | 
								  ((buffer[i+2]&0xFF) << 16) |
								  ((buffer[i+1]&0xFF) <<  8) |
								  ((buffer[i+0]&0xFF) <<  0));
			} else {
				tempVal = (long) (((buffer[i+0]&0xFF) << 24) | 
								  ((buffer[i+1]&0xFF) << 16) |
								  ((buffer[i+2]&0xFF) <<  8) |
								  ((buffer[i+3]&0xFF) <<  0));
			}
			
			sumUpper += tempVal;
			sumLower += (tempVal + 1);
			totalLower = (int) (sumLower & 0x0FFFFFFFFL);
			totalUpper = (int) (sumUpper & 0x0FFFFFFFFL);
		}
		totalLower = (int) ((totalLower) & 0x00000FFFFL);
		totalUpper = (int) (totalUpper & 0x0FFFF0000L);
		retVal = totalUpper | totalLower;
		
		return retVal;
		
	}
	public static void updateChecksumEWEB(byte[] buffer, int checksum, Boolean headerCksum) {
		byte b0 = 0;
		byte b1 = 0;
		byte b2 = 0;
		byte b3 = 0;
		if (littleEndian) {
			b1 = (byte) ((checksum >>  8) & 0x0FF);
			b0 = (byte) ((checksum >>  0) & 0x0FF);		
		} else {
			b0 = (byte) ((checksum >>  8) & 0x0FF);
			b1 = (byte) ((checksum >>  0) & 0x0FF);
		}
		int len = buffer.length;
		if (headerCksum) {
			buffer[0] = b0;
			buffer[1] = b1;	
		} else {
			buffer[20] = b0;
			buffer[21] = b1;
		}
	}
	public static void updateChecksumNonEWEB(byte[] buffer, int checksum) {
		byte b0 = 0;
		byte b1 = 0;
		byte b2 = 0;
		byte b3 = 0;
		if (littleEndian) {
			b3 = (byte) ((checksum >> 24) & 0x0FF);
			b2 = (byte) ((checksum >> 16) & 0x0FF);
			b1 = (byte) ((checksum >>  8) & 0x0FF);
			b0 = (byte) ((checksum >>  0) & 0x0FF);		
		} else {
			b0 = (byte) ((checksum >> 24) & 0x0FF);
			b1 = (byte) ((checksum >> 16) & 0x0FF);
			b2 = (byte) ((checksum >>  8) & 0x0FF);
			b3 = (byte) ((checksum >>  0) & 0x0FF);
		}
		int len = buffer.length;
		buffer[len - 4] = b0;
		buffer[len - 3] = b1;
		buffer[len - 2] = b2;
		buffer[len - 1] = b3;		
	}
	public static boolean processArgs(String [] args) {
		int len = args.length;
		littleEndian = true;
		ctrlModule = false;
		of8Module = false;
		ewebModule = false;

		for (int i=0; i < len;) {
			String option =  args[i];
			if (option.equalsIgnoreCase("-o")) {
				outFName = args[i+1];
				i += 2;			
			} else if (option.equalsIgnoreCase("-f")) {
				inFName = args[i+1];
				i += 2;	
			} else if (option.equalsIgnoreCase("-ctrl")) {
				littleEndian = true;
				ctrlModule = true;
				i += 1;	
			} else if (option.equalsIgnoreCase("-of8")) {
				littleEndian = false;
				of8Module = true;
				i += 1;	
			} else if (option.equalsIgnoreCase("-eweb")) {
				ewebModule = true;
				littleEndian = false;
				i += 1;	
			}  else {
				return false;
			}
		}
		return true;
	}
	public static void showUsage() {
		System.out.println("Usage:\n");
		System.out.println("-f <input filename>		: input file name          : Required\n");
		System.out.println("-o <output filename>	: output file name         : Optional\n");
		System.out.println("-ctrl					: Controller type firmware : Optional\n");
		System.out.println("-of8					: Output Module firmware   : Optional\n");
		System.out.println("-eweb					: Controller type firmware : Optional\n");
	}
	public static void main(String[] args){
		
		RandomAccessFile file = null;
		Writer writer = null;
		int lineCnt = 0;
		try {

			//
			// Process the
			Boolean procArgs = processArgs(args); 
			if (!procArgs || (inFName == null || inFName.equalsIgnoreCase(""))) {
				showUsage();				
			} else {
				file = openFile(inFName);
				byte[] buffer = readFileBuffer(file, 0, (int)file.length());
				int length = buffer.length - 4;
	
				Long startTime = System.currentTimeMillis();
				//
				// generate the checksum intermediate (- last 4 bytes)
				//
				Long checkSumVal1 = 0L;
				Long checkSumVal2 = 0L;
				if (of8Module) {
					checkSumVal1 = (Long)getSimpleSum16(buffer,0, buffer.length-4).longValue();
				
				} else if (ewebModule) {
					checkSumVal1 = (Long)getSimpleSum16(buffer, 22, buffer.length).longValue();
					updateChecksumEWEB(buffer,checkSumVal1.intValue(), false);
					checkSumVal2 = (Long)getSimpleSum16(buffer, 2, 22).longValue();
					updateChecksumEWEB(buffer,checkSumVal2.intValue(), true);
					
				} else if (ctrlModule){
					checkSumVal1 = (Long) computeCheckSum(buffer, length).longValue();
			
					//
					// See what number to add to get back to the 12345678
					//					
					checkSumVal1 = generateCheckSum(sumUpper, sumLower );
					Long checkSumValTest = (Long) computeCheckSum(buffer, length+4).longValue();
					if (checkSumValTest == 0x12345678) {
						System.out.println(" Cntrl module checksum Match");
					} else {
						System.out.println(" Cntrl module checksum MISS Match");
					}	
				}
	
				Long endTime = System.currentTimeMillis();
				long duration = endTime - startTime;
				System.out.println (" New checksum detected.  Value is: " + Integer.toHexString(checkSumVal1.intValue()));
				System.out.println (" Duration is: " + duration/1000);
				
				if (outFName != null && !outFName.equalsIgnoreCase("")) {
					if (ctrlModule || of8Module) {
						updateChecksumNonEWEB(buffer, checkSumVal1.intValue());
						writeFile(outFName, buffer);
					} else if (ewebModule) {
						//updateChecksumEWEB(buffer, checkSumVal.intValue());
						writeFile(outFName, buffer);
					}
				}
				System.out.println("Done");
			}
		} catch (Exception ex) {
				ex.printStackTrace();
		} finally {
			closeOutFile(writer);
			closeFile(file);
		}
	}
}
