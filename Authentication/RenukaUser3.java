import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.io.Writer;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Random;
import java.util.Scanner;


public class RenukaUser3 {

	public int Di, PW, Rd, T, PID, PIN;
	public String com1;

	public static double acosh(double x)
	{
		return Math.log(x + Math.sqrt(x*x - 1.0));
	}

	public static double chebyshev(double x, int z, int n) {
		return Math.cosh(n*acosh(x)%z);
	}

	public static String XOREncode(String st, String key) {
		StringBuilder sb = new StringBuilder();
		for(int i = 0; i < key.length(); i++)
			sb.append((char)(st.charAt(i) ^ key.charAt(i)));
		String str = sb.toString();
		str = str + st.substring(key.length());
		//System.out.println(st.substring(key.length()));
		return str;
	}

	public static String XORDecodekey(String st, String key) {
		StringBuilder sb = new StringBuilder();
		for(int i = 0; i < key.length(); i++)
			sb.append((char)(st.charAt(i) ^ key.charAt(i)));
		String str = sb.toString();
		return str;
	}

	public static String XORDecodeString(String st, String key) {
		StringBuilder sb = new StringBuilder();
		for(int i = 0; i < key.length(); i++)
			sb.append((char)(st.charAt(i) ^ key.charAt(i)));
		String str = sb.toString();
		str = str + st.substring(key.length());
		return str;
	}

	public static String getSha256(String str) {
		MessageDigest digest;
		String encoded = null;
		try {
			digest = MessageDigest.getInstance("SHA-256");
			byte[] hash = digest.digest(str.getBytes(StandardCharsets.UTF_8));
			encoded = Base64.getEncoder().encodeToString(hash);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return encoded;
	} 

	public static void main(String[] args) throws Exception {
		
		Instant responseStart = Instant.now();
		Instant responseEnd = Instant.now();
		long handshakeDuration = -1;
		long sendMsgSize = -1, receiveMsgSize = -1;;
		// memory usage before execution
		long beforeUsedMem=Runtime.getRuntime().totalMemory()-Runtime.getRuntime().freeMemory();
		double Eelec = 50.0;
		double Eamp = 0.1;
		double d = 1.0;
		
						
		long count = 0, total = 0, avgElapsedTime = 0, n= 1;
		final String HOST = "127.0.0.1";
		final int PORT = 4085;
		
		 int IDi = 111;
	     
		String exitStatus= "";
		Socket socket = new Socket(HOST, PORT);
		DataInputStream indata=new DataInputStream(socket.getInputStream());  
		DataOutputStream outdata=new DataOutputStream(socket.getOutputStream());  
		BufferedReader brk=new BufferedReader(new InputStreamReader(System.in)); 
		
		while (count<n) {
			
			
			//exitStatus=brk.readLine();//keyboard input

			if (exitStatus.equalsIgnoreCase("stop")) {
				outdata.writeUTF(exitStatus);
				outdata.flush();
				break;
			}
			
			Instant start = Instant.now(); //time count
			
			////////////////Sending to trusted device //////////////////////
			String content = new Scanner(new File("SC.txt")).useDelimiter("\\Z").next();
    		System.out.println("\n----> "+content);   		
    		String storeRead[] = content.split("<-->"); 
    		String IDSd = storeRead[0];
    		String KGWSd = storeRead[1];
    		
    		Random rnd = new SecureRandom();
			int rs = BigInteger.probablePrime(15, rnd).intValue();
			String send = IDSd+"<-->"+rs;
    		
			String sendsize1 = IDSd+rs;
			sendMsgSize = sendsize1.length()*16;
			
			System.out.println("--->size of 1st send: "+sendMsgSize);   
			
			responseStart = Instant.now(); // start of response time
			
			outdata.writeUTF(send);
			outdata.flush();
			System.out.println("Sent: "+ send);
			System.out.println("rs: "+rs);
			//String encrypt = IDSd+rs;
    		//String cipherText = AES.encrypt(encrypt, KGWSd);
				
			////////////////Receiving from trusted device //////////////////////		
			String input2 = indata.readUTF(); //M6+"<-->"+M8+"<-->"+M10+"<-->"+T3+"<-->"+T4
			
			responseEnd = Instant.now(); // End of response time
			
			System.out.println("Received from D: "+input2);
			
			String DeviceReceived[] = input2.split("<-->");//IDSc+"<-->"+IDSd+"<-->"+cipherTextSd+"<-->"+newcipher;
			String IDSc = DeviceReceived[0];
			String IDSdp = DeviceReceived[1];
			String cipherTextSd = DeviceReceived[2];
			String newcipher = DeviceReceived[3];
			
			String receivesize = DeviceReceived[0]+DeviceReceived[1]+DeviceReceived[2]+DeviceReceived[3];
			receiveMsgSize = receivesize.length()*16;
			
			String decryptedText = AES.decrypt(cipherTextSd, KGWSd); //IDSc+"<-->"+rs+"<-->"+KscSd;
			String deciphered[] = decryptedText.split("<-->");
			String IDScpp = deciphered[0];
    		String rsp = deciphered[1];
    		String KscSd = deciphered[2];
			
    		if(!rsp.equals(""+rs)) {
    			System.out.println("Wrong rc: "+rs);
    			break;
    		}
    		
    		System.out.println("Key between Sc and Sd: "+KscSd);    		
    		String newdecryptedText = AES.decrypt(newcipher, KscSd);
    		String newdeciphered[] = newdecryptedText.split("<-->"); //rs+"<-->"+rc;
			String rspp = newdeciphered[0];
    		String rc = newdeciphered[1];    		
    		System.out.println("rc: "+rc);
    		String encryptedrc = AES.encrypt(rc, KscSd);
    		
    		String sendtodevice2 = IDSd+"<-->"+IDSc+"<-->"+encryptedrc;
    		
    		String sendMesssage2 = IDSd+IDSc+encryptedrc;
    		sendMsgSize = sendMsgSize + sendMesssage2.length()*16;
    		
    		System.out.println("--->size of 2nd send: "+sendMesssage2.length()*16);
    				
    		////////////////Sending to trusted device again //////////////////////
    		outdata.writeUTF(sendtodevice2);
			outdata.flush();
			System.out.println("Sent to device again: "+ sendtodevice2);
    		
    		
			Instant finish = Instant.now(); // time count
			long timeElapsed = Duration.between(start, finish).toMillis();
			System.out.println("timeElapsed: "+timeElapsed+" milliseconds");
			
			count++;
			outdata.writeUTF("stop");
			outdata.flush();
			
			handshakeDuration = Duration.between(start, finish).toMillis();
			long afterUsedMem=Runtime.getRuntime().totalMemory()-Runtime.getRuntime().freeMemory();
			long actualMemUsed=afterUsedMem-beforeUsedMem;
			double memKB = Math.round(((afterUsedMem/(8*1024))*100))/100.0 ;
			long responseTime = Duration.between(responseStart, responseEnd).toMillis();
			double sendEnergy = (Eelec*sendMsgSize)+(Eamp*sendMsgSize*d*d);
			double receiveEnergy = Eelec*receiveMsgSize;
			double totalEnergy = sendEnergy+receiveEnergy;
			
			System.out.println("\nresponse time: "+responseTime+" milliseconds");
			System.out.println("handshake duration: "+handshakeDuration+" milliseconds");
			System.out.println("memory usage: " + memKB + " KB");
			System.out.println("Communication cost (send message size): " + sendMsgSize + " bytes");
			System.out.println("receive message size: " + receiveMsgSize + " bytes");
			System.out.println("Sending Energy: " + sendEnergy + " nJ");
			System.out.println("Receiving Energy: " + receiveEnergy + " nJ");
			System.out.println("Total Energy: " + totalEnergy + " nJ");
			
			String store = responseTime+"\t"+handshakeDuration+"\t"+memKB+"\t"+sendMsgSize+"\t"+receiveMsgSize+"\t"+sendEnergy+"\t"+receiveEnergy+"\t"+totalEnergy;
			Writer output;
			output = new BufferedWriter(new FileWriter("Results.txt", true));  //clears file every time
			output.append(store+"\n");
			output.close();
		}
		
	} 

}
