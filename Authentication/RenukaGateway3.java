import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.SecretKey;

public class RenukaGateway3 {

	public static double acosh(double x) {
		return Math.log(x + Math.sqrt(x * x - 1.0));
	}

	public static double chebyshev(double x, int z, int n) {
		return Math.cosh(n * acosh(x) % z);
	}

	public static String XOREncode(String st, String key) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < key.length(); i++)
			sb.append((char) (st.charAt(i) ^ key.charAt(i)));
		String str = sb.toString();
		str = str + st.substring(key.length());
		// System.out.println(st.substring(key.length()));
		return str;
	}

	public static String XORDecodekey(String st, String key) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < key.length(); i++)
			sb.append((char) (st.charAt(i) ^ key.charAt(i)));
		String str = sb.toString();
		return str;
	}

	public static String XORDecodeString(String st, String key) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < key.length(); i++)
			sb.append((char) (st.charAt(i) ^ key.charAt(i)));
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

	public static void main(String[] args) throws IOException {
		
		final int PORT = 4086;
		final int KscSd = 55667788;
		final int K = 66778899;			
		
		ServerSocket serverSocket = new ServerSocket(PORT);
		Socket clientSocket = serverSocket.accept();
		DataInputStream din = new DataInputStream(clientSocket.getInputStream());
		DataOutputStream dout = new DataOutputStream(clientSocket.getOutputStream());
		
		String input = "", str2 = "";
		while (!input.equals("stop")) {
			
			////////////////receives from trusted device //////////////////////
			input = din.readUTF();
			System.out.println("Received at GW: "+ input);
			
			if (input.equalsIgnoreCase("stop")) {
				break;
			}
			else {
				
					String content = new Scanner(new File("GWmem.txt")).useDelimiter("\\Z").next();
		    		System.out.println("\n----> "+content);   		
		    		String storeRead[] = content.split("<-->"); 
		    		String IDGW = storeRead[0];
		    		String IDSc = storeRead[1];
		    		String IDSd = storeRead[2];
		    		String KGWSc = storeRead[3];
		    		String KGWSd = storeRead[4];
		    		
		    		String DeviceReceived[] = input.split("<-->");//IDSc+"<-->"+IDGW+"<-->"+cipherText;
					String IDScp = DeviceReceived[0];
					String IDGWp = DeviceReceived[1];
					String cipherText = DeviceReceived[2]; //IDSc+"<-->"+IDSd+"<-->"+IDGW+"<-->"+rs+"<-->"+rc;
					
		    		String decryptedText = AES.decrypt(cipherText, KGWSc);
		    		String deciphered[] = decryptedText.split("<-->");//IDSc+"<-->"+IDSd+"<-->"+IDGW+"<-->"+rs+"<-->"+rc;
		    		String IDScpp = deciphered[0];
		    		String IDSdpp = deciphered[1];
		    		String IDGWpp = deciphered[2];
		    		String rs = deciphered[3];
		    		String rc = deciphered[4];
		    		
		    		System.out.println("rspp: "+rs);
		    		System.out.println("rcpp: "+rc);
		    		
		    		String encrypt1 = IDSc+"<-->"+rs+"<-->"+KscSd;
		    		String encrypt2 = IDSd+"<-->"+rc+"<-->"+KscSd+"<-->"+K;
		    		String cipherTextSd = AES.encrypt(encrypt1, KGWSd);
		    		String cipherTextSc = AES.encrypt(encrypt2, KGWSc);
		    		
		    		String sendtoDevice = IDGW+"<-->"+IDSc+"<-->"+cipherTextSd+"<-->"+cipherTextSc;
				////////////////sending to trusted device //////////////////////					
					dout.writeUTF(sendtoDevice); // send to trusted device
					dout.flush();
					System.out.println("Sent to Device from Gateway: "+sendtoDevice);
					System.out.println("Key between GW and Sc: "+K);

				

			}
			
			
		}
		
	}

}
