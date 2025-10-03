package utl;

import java.io.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

import system.EFSystem;

public class EncryptionUtil {
	private String EFS_USER_HOME;
	
	public EncryptionUtil(String username) {
		this.EFS_USER_HOME = EFSystem.pr.getProperty("ROOT_BASE") + username + File.separator;
		File userHome = new File(EFS_USER_HOME);
		if(!userHome.exists()) {
			userHome.mkdir();
		}
	}
	
	// logging in
	public static String hashPasswordWithSalt(String password, String salt) {
		try {
			ProcessBuilder pb = new ProcessBuilder("wsl", "openssl", "passwd", "-1", "-salt", salt, password);
			return executeProcess(pb);
		} catch(Exception e){
			System.out.println("Unable to generate password hash...");
			return "";
		}
	}
	
	// registration
	public static String hashPassword(String password){
		try {
			String salt = generateSalt(8);
			ProcessBuilder pb = new ProcessBuilder("wsl", "openssl", "passwd", "-1", "-salt", salt, password);
			return executeProcess(pb);
		} catch(Exception e) {
			System.out.println("Unable to generate password hash...");
			return "";
		}
	}
	
	public static String generateSalt(int length) throws Exception{
		byte[] salt = new byte[length];
		new SecureRandom().nextBytes(salt);
		
		StringBuilder hexString = new StringBuilder();
		for(byte b: salt) {
			hexString.append(String.format("%02x",b));
		}
		
		return hexString.toString();
	}
	
	// digest: SHA-256, SHA-512, MD5
	public String hash(Path inputPath, String algorithm) throws Exception {
		String validAlg = validateDGSTAlgorithm(algorithm);
		ProcessBuilder pb = new ProcessBuilder("wsl", "openssl", "dgst", "-" + validAlg, convertToWSLPath(inputPath));
		String result = executeProcess(pb);
		
		return result;
	}
	
	// symmetric encryption: AES-128, AES-192, AES-256
	public String encryptAES(Path inputPath, Path destinationPath, String key, String algorithm, String iv) throws Exception{
		Path encryptedPath = destinationPath.resolve(inputPath.getFileName().toString() + ".enc");
		
		String validAlg = validateAESAlgorithm(algorithm);
		
		ProcessBuilder pb = new ProcessBuilder("wsl", "openssl", "enc", "-" + validAlg, "-in", convertToWSLPath(inputPath), "-K", key, "-iv", iv, "-out" , convertToWSLPath(encryptedPath), "-base64");
		executeProcess(pb);
		return encryptedPath.toString();
	}
	
	// symmetric decryption
	public String decryptAES(Path encryptedFilePath, Path destinationPath, String key, String algorithm, String iv) throws Exception{
		Path decryptedPath = Path.of(destinationPath.toString(),encryptedFilePath.getFileName().toString().replace(".enc", ""));
		
		String validAlg = validateAESAlgorithm(algorithm);
		ProcessBuilder pb = new ProcessBuilder("wsl", "openssl", "enc", "-d", "-" + validAlg, "-in", convertToWSLPath(encryptedFilePath), "-K", key, "-iv", iv, "-out", convertToWSLPath(decryptedPath), "-base64");
		executeProcess(pb);
		return decryptedPath.toString();
	}
	
	// generate key for encryption: AES
	public String generateKey(String algorithm, Integer length) throws Exception{
		if("AES".equalsIgnoreCase("AES") && (length.equals(128) || length.equals(192) || length.equals(256))) {
			return executeProcess(new ProcessBuilder("wsl", "openssl", "rand", "-hex", String.valueOf(length/8)));
		} else {
			throw new InvalidKeyException("Invalid key length for the specified algorithm.");
		}
	}
	
	// -------------------------------------------------------------
	
	// RSA encryption
	public String encryptRSA(String data, Path pubKeyPath) throws Exception{
		File tmpFile = File.createTempFile("metadata", ".tmp");
		try(BufferedWriter writer = new BufferedWriter(new FileWriter(tmpFile))){
			writer.write(data);
		}
		
		Path tmpPath = tmpFile.toPath();
		
		File encryptedTmp = File.createTempFile("encrypted", ".bin");
		
		ProcessBuilder pbEncrypt = new ProcessBuilder("wsl", "openssl", "pkeyutl", "-encrypt", "-pubin", "-inkey", convertToWSLPath(pubKeyPath).toString(), "-in", convertToWSLPath(tmpPath), "-out", convertToWSLPath(encryptedTmp.toPath()));
		int encryptExitCode = executeProcessWithExitCode(pbEncrypt);
		
		if(encryptExitCode != 0) {
			throw new RuntimeException("RSA encryption failed with exit code: " + encryptExitCode);
		}
		
		ProcessBuilder pbBase64 = new ProcessBuilder("wsl", "openssl", "base64", "-e", "-in", convertToWSLPath(encryptedTmp.toPath()));
		String b64Encoded = executeProcess(pbBase64).trim();
		
		tmpFile.delete();
		encryptedTmp.delete();
		return b64Encoded;
	}
	
	// RSA decryption
	public String decryptRSA(String encryptedDataB64, Path privateKeyPath) throws Exception{
		byte[] encryptedData = Base64.getMimeDecoder().decode(encryptedDataB64.trim());
		
		File tmpFile = File.createTempFile("encrypted", ".bin");
		try(BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(tmpFile))) {
			bos.write(encryptedData);
		}
		
		Path tmpPath = tmpFile.toPath();
		
		File decryptedTmp = File.createTempFile("decrypted", ".txt");
		
		ProcessBuilder pbDecrypt = new ProcessBuilder("wsl", "openssl", "pkeyutl", "-decrypt", "-inkey", convertToWSLPath(privateKeyPath), "-in", convertToWSLPath(tmpPath), "-out", convertToWSLPath(decryptedTmp.toPath()));
		int decryptExitCode = executeProcessWithExitCode(pbDecrypt);
		if(decryptExitCode != 0) {
			throw new RuntimeException("RSA decryption with exit code " + decryptExitCode);
		}
		
		String decryptedData = new String(Files.readAllBytes(decryptedTmp.toPath()), StandardCharsets.UTF_8);
		
		tmpFile.delete();
		decryptedTmp.delete();
		
		return decryptedData;
	}
	
	// -------------------------------------------------------------------
	
	// digital signature
	public Path signData(Path inputFilePath, Path destinationPath, Path privateKeyPath) throws Exception{
		Path signedPath = destinationPath.resolve(inputFilePath.getFileName().toString() + ".sgn");
		
		ProcessBuilder pb = new ProcessBuilder("wsl", "openssl", "dgst", "-sha256", "-sign", convertToWSLPath(privateKeyPath).toString(), "-out", convertToWSLPath(signedPath).toString(), convertToWSLPath(inputFilePath).toString());
		executeProcess(pb);
		
		ProcessBuilder pbBase64 = new ProcessBuilder("wsl", "openssl", "base64", "-e", "-in", convertToWSLPath(signedPath));
		String b64Encoded = executeProcess(pbBase64).trim();
		
		Files.writeString(signedPath, b64Encoded, StandardCharsets.UTF_8);
		
		return signedPath;
	}
	
	public boolean verifySignature(Path originalFilePath, Path signatureFilePath, Path publicKeyPath) throws Exception{
		String b64Signature = Files.readString(signatureFilePath, StandardCharsets.UTF_8);
		byte[] signatureBytes = Base64.getMimeDecoder().decode(b64Signature);
		Path tmpBinSignature = Files.createTempFile("signature", ".bin");
		Files.write(tmpBinSignature, signatureBytes);
		
		ProcessBuilder pb = new ProcessBuilder("wsl", "openssl", "dgst", "-sha256", "-verify", convertToWSLPath(publicKeyPath).toString(), "-signature", convertToWSLPath(tmpBinSignature).toString(), convertToWSLPath(originalFilePath).toString());
		boolean isVerified = executeProcess(pb).contains("Verified OK");
		
		Files.deleteIfExists(tmpBinSignature);
		return isVerified;
	}
	
	// -------------------------------------------------------------
	
	// mapping windows path to wsl path
	public static String convertToWSLPath(Path windowsPath) {
		String windowsPathStr = windowsPath.toString();

		return "/mnt/" + Character.toLowerCase(windowsPathStr.charAt(0)) + windowsPathStr.substring(2).replace("\\", "/");
	}
	
	public static String executeProcess(ProcessBuilder pb) throws Exception{
		pb.redirectErrorStream(true);
		Process process = pb.start();
		try(BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))){
			StringBuilder output = new StringBuilder();
			String line;
			while((line = reader.readLine()) != null) {
				output.append(line).append("\n");
			}
			int exitCode = process.waitFor();
		    
		    if (exitCode != 0) {
		        throw new RuntimeException("couldn't perform the action...");
		    }
		    
			return output.toString();
		}
	}
	
	private int executeProcessWithExitCode(ProcessBuilder pb) throws Exception {
	    Process process = pb.start();
	    
	    try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
	         BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()))) {
	        
	        StringBuilder output = new StringBuilder();
	        String line;
	        while ((line = reader.readLine()) != null) {
	            output.append(line).append("\n");
	        }

	        StringBuilder errorOutput = new StringBuilder();
	        while ((line = errorReader.readLine()) != null) {
	            errorOutput.append(line).append("\n");
	        }

	        int exitCode = process.waitFor();
	        if (exitCode != 0) {
	            System.err.println("Error output:\n" + errorOutput);
	        }

	        return exitCode;
	    }
	}


	private static String validateDGSTAlgorithm(String algorithm) throws Exception{
		switch(algorithm.toUpperCase()) {
			case "SHA-256":
			case "SHA2-256":
				return "sha256";
			case "SHA-512":
			case "SHA2-512":
				return "sha512";
			case "MD5":
				return "md5";
			default:
				throw new IllegalArgumentException("Unsupported digest algorithm: " + algorithm);	
		}
	}

	private static String validateAESAlgorithm(String algorithm) throws Exception{
		switch(algorithm.toUpperCase()) {
			case "AES-128":
				return "aes-128-cbc";
			case "AES-192":
				return "aes-192-cbc";
			case "AES-256":
				return "aes-256-cbc";
			default:
				throw new IllegalArgumentException("Unsupported AES algorithm: " + algorithm);
		}
	}
}
