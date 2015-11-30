package src.algorithms;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class RSA {
	public KeyPair rsa_generatePairKey() {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		// Create the public and private keys
		KeyPairGenerator generator;
		try {
			generator = KeyPairGenerator.getInstance("RSA", "BC");

			BASE64Encoder b64 = new BASE64Encoder();

			SecureRandom random = createFixedRandom();
			generator.initialize(1024, random);

			KeyPair pair = generator.generateKeyPair();
			Key pubKey = pair.getPublic();
			Key privKey = pair.getPrivate();

			System.out
					.println("publicKey : " + pubKey.getEncoded().toString());
			System.out.println("privateKey : "
					+ privKey.getEncoded().toString());

			return pair;
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	public static SecureRandom createFixedRandom() {
		return new FixedRand();
	}

	private static class FixedRand extends SecureRandom {

		MessageDigest sha;
		byte[] state;

		FixedRand() {
			try {
				this.sha = MessageDigest.getInstance("SHA-1");
				this.state = sha.digest();
			} catch (NoSuchAlgorithmException e) {
				throw new RuntimeException("can't find SHA-1!");
			}
		}

		public void nextBytes(byte[] bytes) {

			int off = 0;

			sha.update(state);

			while (off < bytes.length) {
				state = sha.digest();

				if (bytes.length - off > state.length) {
					System.arraycopy(state, 0, bytes, off, state.length);
				} else {
					System.arraycopy(state, 0, bytes, off, bytes.length - off);
				}

				off += state.length;

				sha.update(state);
			}
		}
	}

	public String rsa_encrypt(String key, String inputData) {
		try {
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
			BASE64Decoder b64 = new BASE64Decoder();
			AsymmetricKeyParameter publicKey = (AsymmetricKeyParameter) PublicKeyFactory
					.createKey(b64.decodeBuffer(key));
			AsymmetricBlockCipher e = new RSAEngine();
			e = new org.bouncycastle.crypto.encodings.PKCS1Encoding(e);
			e.init(true, publicKey);

			byte[] messageBytes = inputData.getBytes();
			byte[] hexEncodedCipher = e.processBlock(messageBytes, 0,
					messageBytes.length);
			return getHexString(hexEncodedCipher);
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (InvalidCipherTextException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (Exception e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		return "";
	}

	public String getHexString(byte[] b) throws Exception {
		String result = "";
		for (int i = 0; i < b.length; i++) {
			result += Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1);
		}
		return result;
	}

	public String rsa_decrypt(String key, String encryptedData) {
		try {
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

			BASE64Decoder b64 = new BASE64Decoder();
			AsymmetricKeyParameter privateKey = (AsymmetricKeyParameter) PrivateKeyFactory
					.createKey(b64.decodeBuffer(key));
			AsymmetricBlockCipher e = new RSAEngine();
			e = new org.bouncycastle.crypto.encodings.PKCS1Encoding(e);
			e.init(false, privateKey);

			byte[] messageBytes = hexStringToByteArray(encryptedData);
			byte[] hexDecodedCipher = e.processBlock(messageBytes, 0,
					messageBytes.length);

			System.out.println(new String(hexDecodedCipher));
			String message = new String(hexDecodedCipher);
			return message;
		} catch (Exception e) {
			System.out.println(e);
		}
		return "";

	}

	public static byte[] hexStringToByteArray(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character
					.digit(s.charAt(i + 1), 16));
		}
		return data;
	}

}
