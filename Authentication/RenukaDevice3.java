import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Writer;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Random;
import java.util.Scanner;

import javax.crypto.SecretKey;

public class RenukaDevice3 {

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

		double Eelec = 50.0;
		double Eamp = 0.1;
		double d = 1.0;
		long size1 = -1, size2 = -1, size3 = -1, size4 = -1, size5 = -1;
		
		final String HOST = "127.0.0.1";
		final int PORTin = 4085;
		final int PORTout = 4086;
		int SIDj = 2222;
    	int Xgwnsj = 6543;
/////////////////////// sockets for the new device ///////////////////////////////////////////////////////////////
		ServerSocket trustedServerSocket = new ServerSocket(PORTin);
		Socket trustedClientSocket = trustedServerSocket.accept();
		DataInputStream Device_indata=new DataInputStream(trustedClientSocket.getInputStream());  
		DataOutputStream Device_outdata=new DataOutputStream(trustedClientSocket.getOutputStream());  

/////////////////////// sockets for the Gateway ///////////////////////////////////////////////////////////////		
		
		Socket GWsocket = new Socket(HOST, PORTout);
		DataInputStream GWindata=new DataInputStream(GWsocket.getInputStream());  
		DataOutputStream GWoutdata=new DataOutputStream(GWsocket.getOutputStream()); 
		
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////		
		String input = "", input2 = "";
		while (!input.equals("stop")) {
			
			//////////////// receives from User //////////////////////
			input = Device_indata.readUTF();
			System.out.println("Received at D from U: "+ input);
			
			if (input.equalsIgnoreCase("stop")) {
				GWoutdata.writeUTF(input);
				GWoutdata.flush();
				break;
				
			}else {
								
				String content = new Scanner(new File("SC.txt")).useDelimiter("\\Z").next();
	    		System.out.println("\n----> "+content);   		
	    		String storeRead[] = content.split("<-->"); 
	    		String IDGW = storeRead[0];
	    		String IDSc = storeRead[1];
	    		String KGWSc = storeRead[2];
	    		
	    		Random rnd = new SecureRandom();
				int rc = BigInteger.probablePrime(15, rnd).intValue();
				
				String UserReceived[] = input.split("<-->");//IDSd+<-->+rs
				String IDSd = UserReceived[0];
				String rs = UserReceived[1];

				size1 = (UserReceived[0].length()+UserReceived[1].length())*16;
				
				String encrypt = IDSc+"<-->"+IDSd+"<-->"+IDGW+"<-->"+rs+"<-->"+rc;
	    		String cipherText = AES.encrypt(encrypt, KGWSc);
	    		
	    		String sendtoGW = IDSc+"<-->"+IDGW+"<-->"+cipherText;
	    		
	    		String sendtoGWsize = ""+IDSc+IDGW+cipherText;
				size2 = sendtoGWsize.length()*16;
	    		
	    		System.out.println("rs: "+rs);
	    		System.out.println("rc: "+rc);
	    		    		
				////////////////Sending to Gateway //////////////////////
				GWoutdata.writeUTF(sendtoGW);
				GWoutdata.flush();
				System.out.println("sent to gateway: "+sendtoGW);
				
				////////////////receives from Gateway //////////////////////
				input2 = GWindata.readUTF(); 
				System.out.println("received from GW: "+ input2);
				String GWReceived[] = input2.split("<-->");//IDGW+"<-->"+IDSc+"<-->"+cipherTextSd+"<-->"+cipherTextSc;
				String IDGWp = GWReceived[0];
				String IDScp = GWReceived[1];
				String cipherTextSd = GWReceived[2];
				String cipherTextSc = GWReceived[3];
				
				size3 = (GWReceived[0].length()+GWReceived[1].length()+GWReceived[2].length()+GWReceived[3].length())*16;
				
				String decryptedText = AES.decrypt(cipherTextSc, KGWSc); //IDSd+"<-->"+rc+"<-->"+KscSd+"<-->"+K;
				String deciphered[] = decryptedText.split("<-->");
	    		String IDSdp = deciphered[0];
	    		String rcp = deciphered[1];
	    		String KscSd = deciphered[2];
	    		String K = deciphered[3];
	    		//System.out.println("Key between Sc and Sd: "+KscSd);
	    		if(!rcp.equals(""+rc)) {
	    			System.out.println("Wrong rc: "+rc);
	    			break;
	    		}
	    		System.out.println("Key between GW and Sc: "+K); 
	    		
	    		String newencrypt = rs+"<-->"+rc;
	    		String newcipher = AES.encrypt(newencrypt, KscSd);
	    		
	    		String sendtoUser = IDSc+"<-->"+IDSd+"<-->"+cipherTextSd+"<-->"+newcipher;
				
	    		String sizemsgtoGW = IDSc+IDSd+cipherTextSd+newcipher; 
				size4 = sizemsgtoGW.length()*16;
				
	    		////////////////Sending to User //////////////////////
				Device_outdata.writeUTF(sendtoUser);
				Device_outdata.flush();
				System.out.println("Send from Device to User: "+sendtoUser);
				
////////////////receives from User //////////////////////
				String input3 = Device_indata.readUTF();
				System.out.println("Received at D from U again: "+ input3);
				String newUserReceived[] = input3.split("<-->");//IDSd+"<-->"+IDSc+"<-->"+encryptedrc;
				String IDSdpp = newUserReceived[0];
				String IDScpp = newUserReceived[1];
				String encryptedrc = newUserReceived[2];
				
				size5 = (newUserReceived[0].length()+newUserReceived[1].length()+newUserReceived[2].length())*16;
				
				String rcpp = AES.decrypt(encryptedrc, KscSd); //decrypts rc
				if(!rcpp.equals(""+rc)) {
	    			System.out.println("Wrong rc: "+rc);
	    			break;
	    		}
				System.out.println("Key between Sc and Sd: "+KscSd);
			}
			
			long receiveMsgSize = size1+size3+size5;
			long sendMsgSize = size2+size4;
			long afterUsedMem=Runtime.getRuntime().totalMemory()-Runtime.getRuntime().freeMemory();
			double memKB = Math.round(((afterUsedMem/(8*1024))*100))/100.0 ;
			double sendEnergy = (Eelec*sendMsgSize)+(Eamp*sendMsgSize*d*d);
			double receiveEnergy = Eelec*receiveMsgSize;
			double totalEnergy = sendEnergy+receiveEnergy;
			
			System.out.println("memory usage: " + memKB + " KB");
			System.out.println("Communication cost (send message size): " + sendMsgSize + " bytes");
			System.out.println("receive message size: " + receiveMsgSize + " bytes");
			System.out.println("Sending Energy: " + sendEnergy + " nJ");
			System.out.println("Receiving Energy: " + receiveEnergy + " nJ");
			System.out.println("Total Energy: " + totalEnergy + " nJ");
			
			String store = memKB+"\t"+sendMsgSize+"\t"+receiveMsgSize+"\t"+sendEnergy+"\t"+receiveEnergy+"\t"+totalEnergy;
			Writer output;
			output = new BufferedWriter(new FileWriter("Results.txt", true));  //clears file every time
			output.append(store+"\n");
			output.close();
		}

	}

}
