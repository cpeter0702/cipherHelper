package utils;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class CipherMain {

    private static final String PRIVATEKEY_PEM_PATH = "C:\\tmp\\ace\\private_key.pem";
    private static final String PUBLICKEY_PEM_PATH = "C:\\tmp\\ace\\public_key.pem";

    public static void main (String[] args) throws Exception {
        CipherUtils cUtils = new CipherUtils();
        String inputMsg = "{ \"signStr\":\"7866587759667177365a2b6a5530676430375a363344466263752f2f3057357465315245784b6c427973474c72426156674845627567784f4147683337535030436a4a39694f6b4f4f324b50486b7a5476784975626f736473573551724f38784c48697a555942633741786b6c2b344335536b4b354e4266306354796945584b5432624a4a724c4165774f56796550417355484f317a4b424b2b566e37643951695a7a4a79694964736d2b4532387835316267456a736875474a6d6335425a6145783336675a67435039564f634c4d6433694b5977415066584b53356e2b346134535148694f6b757a384c45704a596f73373856796e74614c7154552b4647646a4a3752426a30786647674c63774e5959416170624863476738787651674d635a6d3871344b6d2b4c732f5a6a31466f6e304c704e513667364a4467556a6e53306c33457658364d524643346263496a624872572f4b6f762b52762f5749633366364e484d65632f3036463730754876706867495431706e37434765696f6c414945536b68673869726344494b4737556853443766544868374471526849527442724f6333745076386143766433424e6378655a49582f71485578586551762f58554433774e514450587757475777754b6f66455232665758593162446f773549564f4d553748504f3332576f756975694f556176616435744771652f516379422b554462334a7a36653076776a42303266532b7657552f647163713633387874396953476f6e3443543276374b556d70514630676636477549354850776d534f59413359332b792f7937515a37706c6f4470796a31693070395746335079324e34753859482b50387356784756683667783969634f667837454935496b4433346752527444506f6c5931504e3142595664585179756547613942634d2b32794f42414d59624a7a6655413d\", \"originalMsg\":[ { \"resource\":{ \"resourceType\":\"Composition\", \"id\":\"17be23f8af3-543d105a-792d-4656-9279-759bddf76014\", \"status\":\"final\", \"type\":{ \"coding\":[ { \"system\":\"http:\\/\\/loinc.org\", \"code\":\"LP6464-4\", \"display\":\"Nucleic acid amplification with probe detection\" } ] }, \"subject\":{ \"reference\":\"Patient\\/17baa20dade-a04cbe92-2250-4bc0-8fb8-1876367b3c65\" }, \"date\":\"2021-09-03T05:28:05.086Z\", \"author\":[ { \"reference\":\"Practitioner\\/17bbffe1701-8c03420f-642f-4f4d-888f-f69014d1bf20\", \"display\":\"周惟誼\" } ], \"title\":\"PCR Certificate2021-09-03T05:28:05.086Z\", \"custodian\":{ \"reference\":\"Organization\\/17ba99eed9d-c5f9ef7c-076b-4c23-a378-5604361bb0f7\" }, \"section\":[ { \"entry\":[ { \"reference\":\"Patient\\/17baa20dade-a04cbe92-2250-4bc0-8fb8-1876367b3c65\" }, { \"reference\":\"Observation\\/17bc9db5598-22624e68-46c7-4406-a555-1042d45eeb20\" }, { \"reference\":\"Organization\\/17ba99eed9d-c5f9ef7c-076b-4c23-a378-5604361bb0f7\" } ] } ] } }, { \"resource\":{ \"resourceType\":\"Organization\", \"id\":\"17ba99eed9d-c5f9ef7c-076b-4c23-a378-5604361bb0f7\", \"identifier\":[ { \"system\":\"https:\\/\\/www.vghtpe.gov.tw\\/\", \"value\":\"臺北榮民總醫院\" } ], \"name\":\"臺北榮民總醫院 (VGHTPE)\", \"address\":[ { \"country\":\"R.O.C.\" } ] } }, { \"resource\":{ \"resourceType\":\"Patient\", \"id\":\"17baa20dade-a04cbe92-2250-4bc0-8fb8-1876367b3c65\", \"identifier\":[ { \"system\":\"urn:oid:0.1.2.3.4.5.6.7\", \"value\":\"A123456789\" } ], \"name\":[ { \"family\":\"朱\", \"given\":[ \"原嘉\" ] }, { \"family\":\"CHU\", \"given\":[ \"YUAN-CHIA\" ] } ], \"birthDate\":\"1990-01-01\" } }, { \"resource\":{ \"resourceType\":\"Observation\", \"id\":\"17bc9db5598-22624e68-46c7-4406-a555-1042d45eeb20\", \"status\":\"final\", \"code\":{ \"coding\":[ { \"system\":\"http:\\/\\/loinc.org\", \"code\":\"LP6464-4\", \"display\":\"Nucleic acid amplification with probe detection\" } ] }, \"effectivePeriod\":{ \"start\":\"2021-07-01T10:30:10+08:00\", \"end\":\"2021-07-08T10:30:10+08:00\" }, \"performer\":[ { \"reference\":\"Organization\\/17a37ae66d0-25f31cb7-4c65-4081-ac21-7b6ce9a5e9e1\" } ], \"valueString\":\"Negative\" } } ] }";
        RSAPrivateKey privateKey = cUtils.getPrivateKey(PRIVATEKEY_PEM_PATH);
        RSAPublicKey publicKey = cUtils.getPublicKey(PUBLICKEY_PEM_PATH);

        // Step 1
        String serverHashStr = cUtils.doHashing(inputMsg);
        System.out.println("Server - dohash: " + serverHashStr);
        
        // Step 2
        byte[] serverEncodeMsg = cUtils.encodeByPrivateKey(privateKey, serverHashStr);
        System.out.println("Server - encode: " + cUtils.convertByteArray2String(serverEncodeMsg));
        
        // Step 3
        String serverSignStr = cUtils.base64Byte2Str(privateKey, serverEncodeMsg);
        System.out.println("Server - signature: " + serverSignStr);
        
        
        // client
        
        byte[] clientUnSign = cUtils.base64Str2Byte(publicKey, serverEncodeMsg, serverSignStr);
        System.out.println("Client - unSign: " + cUtils.convertByteArray2String(clientUnSign));
        
        byte[] decodeMsg = cUtils.decodeByPublicKey(publicKey, clientUnSign);
        System.out.println("Client - decode: " + new String(decodeMsg));
        

    }
    
    
	
}
