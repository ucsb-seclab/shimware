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

public class AllenBradlyCkSumValidator {
	private static String inFName = "";
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

	public static int getFletcher32(byte[] bytes, int length, int limit) {
	    int s1 = 0xffff, s2 = 0xffff;
	    for (int i = 0; i < length;) {
	        for (int end = Math.min(i + limit, length); i < end;) {
	            int x = ((bytes[i++] & 0xff) << 8) | (bytes[i++] & 0xff);
	            s2 += s1 += x;
	        }
	        s1 = (s1 & 0xffff) + (s1 >>> 16);
	        s2 = (s2 & 0xffff) + (s2 >>> 16);
	    }
	    s1 = (s1 & 0xffff) + (s1 >>> 16);
	    s2 = (s2 & 0xffff) + (s2 >>> 16);
	    return (s2 << 16) | s1;
	}
	public static int getFletcher32Short(byte[] bytes, int length, int len) {
		int c0, c1;
        int i;
        int j = 0;

        for (c0 = c1 = 0; len >= 360; len -= 360) {
                for (i = 0; i < 360; ++i) {
                	int temp = ((bytes[i+0] & 0x0FF) << 8) | ((bytes[i+1] & 0x0FF) << 0);
                        c0 = c0 + temp;
                        c1 = c1 + c0;
                }
                c0 = c0 % 65535;
                c1 = c1 % 65535;
        }
        for (i = 0; i < len; ++i) {
        	int temp = ((bytes[i+0] & 0x0FF) << 8) | ((bytes[i+1] & 0x0FF) << 0);
                c0 = c0 + temp;
                c1 = c1 + c0;
        }
        c0 = c0 % 65535;
        c1 = c1 % 65535;
        return (c1 << 16 | c0);
	    
	}
	public static Long adler32(byte[] buffer) {
		Checksum checksum = new Adler32();
		checksum.update(buffer,0,buffer.length);
		return checksum.getValue();
	}
	
	public static boolean processArgs(String [] args) {
		int len = args.length;

		for (int i=0; i < len;) {
			String option =  args[i];
			if (option.equalsIgnoreCase("-f")) {
				inFName = args[i+1];
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
	}
	
	public static void main(String[] args){
		
		RandomAccessFile file = null;
		Writer writer = null;

		try {
			Boolean procArgs = processArgs(args); 
			if (!procArgs || (inFName == null || inFName.equalsIgnoreCase(""))) {
				showUsage();	
				throw new IOException();
			}
				

			//String inFName = "C:/Users/ajr117/Desktop/Package/1756-L61_20.58/PN-433399.bin";
			//String inFName = "C:/Users/ajr117/Desktop/Package/L64.v19.11.16/PN-85386.bin";
			//String inFName = "C:/Users/ajr117/Desktop/Package/L64.v20.12.79/PN-156388.bin";
			//String inFName = "C:/Users/ajr117/Desktop/Package/L64.v20.14.83/PN-274932.bin";
			//String inFName = "C:/Users/ajr117/Desktop/Package/L64.v20.14.83/PN-274932.bin";
			//String inFName = "C:/Users/ajr117/Desktop/Package/OF8.v1.5/99223704.bin";
			file = openFile(inFName);
			byte[] buffer = readFileBuffer(file, 0, (int)file.length());

			int length = (int) file.length();
			
			//
			// Determine what the checksum should be 
			//
			int totalUpper = 0;
			Long sumUpper = 0L;
			int totalLower = 0;
			Long sumLower = 0L;
			Long tempVal = 0L;
			for (int i = 0; i < length; i+=4) {					
				tempVal = (long) (((buffer[i+3]&0xFF) << 24) | 
						((buffer[i+2]&0xFF) << 16) |
						((buffer[i+1]&0xFF) <<  8) |
						((buffer[i+0]&0xFF) <<  0));
				
				sumUpper += tempVal;
				sumLower += (tempVal + 1);
				totalLower = (int) (sumLower & 0x0FFFFFFFFL);
				totalUpper = (int) (sumUpper & 0x0FFFFFFFFL);
			}
			totalLower = (int) ((totalLower) & 0x00000FFFFL);
			totalUpper = (int) (totalUpper & 0x0FFFF0000L);
			
			System.out.println("32 bit blocks Reversed The sum is: " + Integer.toHexString(totalUpper));
			System.out.println("\n");
			System.out.println("32 bit blocks adding 1 Reversed The sum is: " + Integer.toHexString(totalLower));
			System.out.println("\n");
			System.out.println("Allen Bradly Checksum (- last 4) : " + Integer.toHexString(totalUpper | totalLower));
			
	
		} catch (Exception ex) {
				ex.printStackTrace();
		} finally {
			closeOutFile(writer);
			closeFile(file);
		}
	}
}

