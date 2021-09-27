package utils;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class CipherMain {

	private static final String PRIVATEKEY_PEM_PATH = "C:\\tmp\\ace\\private_key.pem";
	private static final String PUBLICKEY_PEM_PATH = "C:\\tmp\\ace\\public_key.pem";

	public static void main(String[] args) throws Exception {
		CipherUtils cUtils = new CipherUtils();
		String inputMsg = "{\"resource\":{\"resourceType\":\"Composition\",\"id\":\"17be23f8af3-543d105a-792d-4656-9279-759bddf76014\",\"status\":\"final\",\"type\":{\"coding\":[{\"system\":\"http://loinc.org\",\"code\":\"LP6464-4\",\"display\":\"Nucleic acid amplification with probe detection\"}]},\"subject\":{\"reference\":\"Patient/17baa20dade-a04cbe92-2250-4bc0-8fb8-1876367b3c65\"},\"date\":\"2021-09-03T05:28:05.086Z\",\"author\":[{\"reference\":\"Practitioner/17bbffe1701-8c03420f-642f-4f4d-888f-f69014d1bf20\",\"display\":\"���盲\"}],\"title\":\"PCR Certificate2021-09-03T05:28:05.086Z\",\"custodian\":{\"reference\":\"Organization/17ba99eed9d-c5f9ef7c-076b-4c23-a378-5604361bb0f7\"},\"section\":[{\"entry\":[{\"reference\":\"Patient/17baa20dade-a04cbe92-2250-4bc0-8fb8-1876367b3c65\"},{\"reference\":\"Observation/17bc9db5598-22624e68-46c7-4406-a555-1042d45eeb20\"},{\"reference\":\"Organization/17ba99eed9d-c5f9ef7c-076b-4c23-a378-5604361bb0f7\"}]}]}}";
		RSAPrivateKey privateKey = cUtils.getPrivateKey(PRIVATEKEY_PEM_PATH);
		RSAPublicKey publicKey = cUtils.getPublicKey(PUBLICKEY_PEM_PATH);

		// Step 1
		String serverHashStr = cUtils.doHashing(inputMsg);
		System.out.println("Server - dohash: " + serverHashStr);

		// Step 2
		byte[] serverEncodeMsg = cUtils.encodeByPrivateKey(privateKey, serverHashStr);
		System.out.println("Server - encode: " + cUtils.convertByteArray2String(serverEncodeMsg));

		// Step 3
		String serverSignStr = cUtils.base64Byte2Str(serverEncodeMsg);
		System.out.println("Server - signature: " + serverSignStr);

		// client

		byte[] clientUnSign = cUtils.base64Str2Byte(serverSignStr);
		System.out.println("Client - unSign: " + cUtils.convertByteArray2String(clientUnSign));

		byte[] decodeMsg = cUtils.decodeByPublicKey(publicKey, clientUnSign);
		System.out.println("Client - decode: " + new String(decodeMsg));

	}

}
