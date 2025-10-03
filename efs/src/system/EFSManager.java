package system;

import java.util.*;
import java.nio.file.*;
import java.nio.charset.*;
import java.util.stream.*;
import utl.*;

public class EFSManager {
	public static Random rand = new Random();
	public static Path PROHIBITED = Path.of(EFSystem.pr.getProperty("PROHIBITED_DOWNLOAD_DIR"));
	
	private EncryptionUtil eu;
	private User user;
	private Path rootDir;
	private Path userHostDir;
	private Path rootDirAbs;
	private static final Path EFS_SHARED = Path.of(EFSystem.pr.getProperty("SHARED"));
	private static final Path EFS_SHARED_ABS = Path.of(EFSystem.pr.getProperty("SHARED_ABS"));
	static {
		try {
		    if(!Files.exists(EFS_SHARED)) {
		    	Files.createDirectories(EFS_SHARED);
		    }
		} catch(Exception e) {
			e.printStackTrace();
		}
	}
	
	public EFSManager(String username) {
		this.eu = new EncryptionUtil(username);
		this.user = EFSystem.EFSusers.get(username);
		this.rootDir = Paths.get(EFSystem.pr.getProperty("ROOT_BASE") + username);
		this.rootDirAbs = Paths.get(EFSystem.pr.getProperty("ROOT_BASE_ABS") + username);
		this.userHostDir = Paths.get(EFSystem.pr.getProperty("HOST_DIR") + username);
		
		initializeUserDir();
		initializeUserHostDir();
		
		System.out.println();
		System.out.println("Welcome to your home EFS directory!");
		
		listUserFiles();
	}
	
	private void initializeUserDir() {
		try {
			if(!Files.exists(rootDir) || !Files.isDirectory(rootDir)) {
				Files.createDirectories(rootDir);
			}
		} catch(Exception e) {
			e.printStackTrace();
		}
	}
	
	private void initializeUserHostDir() {
		try {
			if(!Files.exists(userHostDir) || !Files.isDirectory(userHostDir)) {
				Files.createDirectories(userHostDir);
			}
		} catch(Exception e) {
			e.printStackTrace();
		}
	}
	
	public void listUserFiles() {
		System.out.println();
			
		try {
			System.out.println("Content of your EFS home directory: ");
			listFilesRecursively(rootDir,0);
		} catch(Exception e) {
			e.printStackTrace();
		}
	}
	
	public void listSharedFiles() {
		System.out.println();
			
		try {
			System.out.println("Content of EFS SHARED directory: ");
			listFilesRecursively(EFS_SHARED,0);
		} catch(Exception e) {
			e.printStackTrace();
		}
	}
	
	private void listFilesRecursively(Path dir, int depth) throws Exception{
		try(Stream<Path> paths = Files.list(dir)){
			List<Path> fileList = paths.filter(path -> Files.isDirectory(path) || path.getFileName().toString().endsWith(".enc")).sorted(Comparator.comparingInt(path -> path.getNameCount())).toList();
			
			// directory is empty
			if(fileList.isEmpty() && depth == 0) {
	            System.out.println("This directory is empty.");
	            System.out.println();
	            return;
	        }
			
			for(Path path : fileList) {
				String indent = "     ".repeat(depth);
	        		
				if(Files.isDirectory(path)) {
					System.out.println(indent + "[DIR]: " + path.getFileName());
					listFilesRecursively(path, depth+1);
				} else {
					System.out.println(indent + "[FILE]: " + path.getFileName());
				}
			}
		}
	}
	
	// -------------------------------------------------------------
	
	public boolean addFile(String sourceFile, String targetDir) throws Exception{
		Path sourceFilePath = Path.of(sourceFile).normalize();
		Path destinationDir = rootDirAbs.resolve(targetDir).normalize();
		if(!destinationDir.startsWith(rootDirAbs)) {
			System.out.println("Invalid directory path! You can only add files inside your directory!");
			return false;
		}
		
		if(!Files.exists(destinationDir) || !Files.isDirectory(destinationDir)) {
			System.out.println("Invalid target directory: '" + destinationDir + "'");
		}	
		
		// randomly choosing an algorithm
		String aesAlgs[] = {"AES-128", "AES-192", "AES-256"};
		String selectedAlg = aesAlgs[rand.nextInt(aesAlgs.length)];
		String algLen[] = selectedAlg.split("-");
		
		// generating key, iv, hash of plain text
		String key = eu.generateKey(algLen[0].trim(),Integer.parseInt(algLen[1].trim())).trim();
		String iv = EncryptionUtil.executeProcess(new ProcessBuilder("wsl", "openssl", "rand", "-hex", "16")).trim();
		
		String dgstAlgs[] = {"SHA-256", "SHA-512", "MD5"};
		String selectedDgstAlg = dgstAlgs[rand.nextInt(dgstAlgs.length)];
		String hash = eu.hash(sourceFilePath, selectedDgstAlg).trim();
		
		String encryptedFile = eu.encryptAES(sourceFilePath,destinationDir,key,selectedAlg,iv);
		Path encryptedFilePath = destinationDir.resolve(Path.of(encryptedFile).getFileName());		
		if(!Files.exists(encryptedFilePath)) {
			System.out.println("ERROR: Encrypted file was NOT created!");
			return false;
		}
		
		// generating metadata
		Path metadataFilePath = destinationDir.resolve(Path.of(encryptedFile).getFileName().toString().replace(".enc", ".meta"));
		String hashAlg = hash.split("\\(")[0].trim();
		String onlyHash = hash.split("= ")[1].trim();
		String metadataPlain = "hash=" + hashAlg + ":" + onlyHash;
		
		// encipherment with rsa
		String encryptedAlg = eu.encryptRSA(selectedAlg, user.getPublicKeyPath());
		String encryptedKey = eu.encryptRSA(key, user.getPublicKeyPath());
		String encryptedIV = eu.encryptRSA(iv, user.getPublicKeyPath());
		String metadata = metadataPlain + "\nalgorithm=" + encryptedAlg + "\niv=" + encryptedIV + "\nkey=" + encryptedKey;
		Files.write(metadataFilePath, metadata.getBytes(StandardCharsets.UTF_8));
		
		System.out.println("File and successfully added to EFS system: " + destinationDir.toString());
		return true;
	}
	
	public boolean downloadFile(String encryptedFile, String destination, String userPrivateKey) throws Exception{
		Path encryptedFilePath = rootDirAbs.resolve(encryptedFile).normalize();
		Path metadataFilePath = encryptedFilePath.resolveSibling(encryptedFilePath.getFileName().toString().replace(".enc",".meta"));
		
		if(!Files.exists(encryptedFilePath) || !Files.exists(metadataFilePath)) {
			System.out.println("Couldn't download the file...");
			return false;
		}
		
		Path destinationPath = userHostDir.resolve(destination).normalize();
		
		// working with metadata
		List<String> metadataLines = Files.readAllLines(metadataFilePath, StandardCharsets.UTF_8);
		
		if(metadataLines.size() < 4) {
			throw new IllegalArgumentException("Metadata is incomplete or corrupted.");
		}
		
		String algHash = metadataLines.get(0).split("=")[1].trim();
		String hashAlg = algHash.split(":")[0].trim();
		String hashOnly = algHash.split(":")[1].trim();
		
		// encrypted part of metadata
		StringBuilder ciphertextBuilder = new StringBuilder();
		for(int i=1; i<metadataLines.size(); i++) {
			ciphertextBuilder.append(metadataLines.get(i));
		}
		String metadata = ciphertextBuilder.toString();
		
		int algIndex = metadata.indexOf("algorithm=");
		int ivIndex = metadata.indexOf("iv=");
		int keyIndex = metadata.indexOf("key=");
		
		if(algIndex == -1 || ivIndex == -1 || keyIndex == -1) {
			throw new IllegalArgumentException("Metadata does not contain a key field.");
		}
		
		String encryptedAlg = metadata.substring(algIndex + "algoritmh=".length(), ivIndex).trim();
		String algorithm = eu.decryptRSA(encryptedAlg, user.getPrivateKeyPath());
		String encryptedIV = metadata.substring(ivIndex + "iv=".length(), keyIndex).trim();
		String iv = eu.decryptRSA(encryptedIV, user.getPrivateKeyPath());
		String encryptedKey = metadata.substring(keyIndex + "key=".length()).trim();
		String key = eu.decryptRSA(encryptedKey, user.getPrivateKeyPath());
		
		// decrypt the main file
		String decryptedFile = eu.decryptAES(encryptedFilePath,destinationPath,key,algorithm,iv);
		System.out.println("Sucessfully downloaded to " + decryptedFile);
		
		// validate hash integrity
		String newHash = eu.hash(Path.of(decryptedFile), hashAlg);
		String newHashOnly = newHash.split("= ")[1].trim();
				
		if(!newHashOnly.equals(hashOnly)) {
			System.out.println("Your file has been modified!");
		}
		return true;
	}
	
	
	public boolean addFileToShared(String sourceFile, String recipientUsername) throws Exception{
		Path sourceFilePath = Path.of(sourceFile).normalize();
		
		// signing source file
		eu.signData(sourceFilePath,EFS_SHARED_ABS,user.getPrivateKeyPath());
		
		// randomly choosing an algorithm
		String aesAlgs[] = {"AES-128", "AES-192", "AES-256"};
		String selectedAlg = aesAlgs[rand.nextInt(aesAlgs.length)];
		String algLen[] = selectedAlg.split("-");
		
		// generating key and iv
		String key = eu.generateKey(algLen[0].trim(),Integer.parseInt(algLen[1].trim())).trim();
		String iv = EncryptionUtil.executeProcess(new ProcessBuilder("wsl", "openssl", "rand", "-hex", "16")).trim();
		
		User recipient = EFSystem.EFSusers.get(recipientUsername);
		if(recipient == null) {
			System.out.println("User with entered username doesn't exist!");
			return false;
		}
		
		// data encryption
		String encryptedFile = eu.encryptAES(sourceFilePath,EFS_SHARED_ABS,key,selectedAlg,iv);
		Path encryptedFilePath = EFS_SHARED_ABS.resolve(Path.of(encryptedFile).getFileName());
		
		if(!Files.exists(encryptedFilePath)) {
			System.out.println("ERROR: Encrypted file was NOT created!");
			return false;
		}
		
		// encipherment with rsa
		String encryptedAlg = eu.encryptRSA(selectedAlg, recipient.getPublicKeyPath());
		String encryptedIV = eu.encryptRSA(iv, recipient.getPublicKeyPath());
		String encryptedKey = eu.encryptRSA(key, recipient.getPublicKeyPath());
		String encryptedSender = eu.encryptRSA(user.getUsername(), recipient.getPublicKeyPath());

		String metadata = "algorithm=" + encryptedAlg + "\niv=" + encryptedIV + "\nkey=" + encryptedKey + "\nsender=" + encryptedSender;
		Path metadataFilePath = EFS_SHARED_ABS.resolve(Path.of(encryptedFile).getFileName().toString().replace(".enc", ".meta"));
		Files.write(metadataFilePath, metadata.getBytes(StandardCharsets.UTF_8));
		
		System.out.println("File successfully added to EFS shared folder.");
		return true;
	}
	
	public boolean downloadFileFromShared(String encryptedFile, String destination) throws Exception{
		Path encryptedFilePath = EFS_SHARED_ABS.resolve(encryptedFile).normalize();
		Path metadataFilePath = encryptedFilePath.resolveSibling(encryptedFilePath.getFileName().toString().replace(".enc", ".meta"));
		Path signatureFilePath = encryptedFilePath.resolveSibling(encryptedFilePath.getFileName().toString().replace(".enc", ".sgn"));
		
		if(!Files.exists(encryptedFilePath) || !Files.exists(metadataFilePath) || !Files.exists(signatureFilePath)) {
			System.out.println("The specified file doesn't exist or is incomplete!");
			return false;
		}
		
		Path destinationPath = userHostDir.resolve(destination).normalize();
		
		// reading and parsing metadata
		List<String> metadataLines = Files.readAllLines(metadataFilePath, StandardCharsets.UTF_8);
		if(metadataLines.size() < 4) {
			throw new IllegalArgumentException("Metadata is incomplete or corrupted!");
		}
		
		StringBuilder ciphertextBuilder = new StringBuilder();
		for(int i=0; i<metadataLines.size(); i++) {
			ciphertextBuilder.append(metadataLines.get(i));
		}
		String metadata = ciphertextBuilder.toString();
		
		int algIndex = metadata.indexOf("algorithm=");
		int ivIndex = metadata.indexOf("iv=");
		int keyIndex = metadata.indexOf("key=");
		int senderIndex = metadata.indexOf("sender=");
		
		if(algIndex == -1 || ivIndex == -1 || keyIndex == -1 || senderIndex == -1) {
			throw new IllegalArgumentException("Metadata does not contain a key field.");
		}
		
		String encryptedAlg = metadata.substring(algIndex + "algoritmh=".length(), ivIndex).trim();
		String algorithm = eu.decryptRSA(encryptedAlg, user.getPrivateKeyPath());
		String encryptedIV = metadata.substring(ivIndex + "iv=".length(), keyIndex).trim();
		String iv = eu.decryptRSA(encryptedIV, user.getPrivateKeyPath());
		String encryptedKey = metadata.substring(keyIndex + "key=".length(), senderIndex).trim();
		String key = eu.decryptRSA(encryptedKey, user.getPrivateKeyPath());
		String encryptedSender = metadata.substring(senderIndex + "sender=".length()).trim();
		String sender = eu.decryptRSA(encryptedSender, user.getPrivateKeyPath());
		
		Path senderPublicKeyPath = EFSystem.getPublicKey(sender);
		if(senderPublicKeyPath == null) {
			System.out.println("Invalid action!");
			return false;
		}
		
		String decryptedFile = eu.decryptAES(encryptedFilePath, destinationPath, key, algorithm, iv);
		Path decryptedFilePath = destinationPath.resolve(Path.of(decryptedFile).getFileName());
		
		// verify signature
		boolean isSignatureValid = eu.verifySignature(decryptedFilePath,signatureFilePath,senderPublicKeyPath);		
		if(!isSignatureValid) {
			System.out.println("The file might have been tampered with!");
			return false;
		}
		
		System.out.println();
		System.out.println("File from user " + sender);
		System.out.println("File successfully downloaded to " + decryptedFile);
		return true;
	}
	
	// -------------------------------------------------------------
	
	public void createDirectory(String parentDir, String dirName) throws Exception{
		Path parentPath = rootDir.resolve(parentDir).normalize();
		if(!parentPath.startsWith(rootDir)) {
			System.out.println("Invalid path! You can only create directories inside your root directory.");
			return;
		}
		
		Path dirPath = parentPath.resolve(dirName);
		if(!Files.exists(dirPath)) {
			Files.createDirectories(dirPath);
			System.out.println("Directory '" + dirPath + "' created");
		} else {
			System.out.println("Specified directory already exists!");
		}
	}
		
	public void deleteDirectory(String dirPath) throws Exception{
		Path directory = rootDir.resolve(dirPath).normalize();
		
		if(!directory.startsWith(rootDir)) {
			System.out.println("Invalid path! You can only delete directories inside your root directory.");
			return;
		}
		
		if(directory.equals(rootDir)) {
			System.out.println("You cannot delete the root directory!");
			return;
		}
		
		if(!Files.exists(directory)) {
			System.out.println("Directory doesn't exist!");
			return;
		}
		
		Files.walk(directory).sorted(Comparator.reverseOrder()).forEach(path -> {
			try {
				Files.delete(path);
			} catch(Exception e) {
				System.err.println("Failed to delete '" + path + "'");
			}
		});
		
		System.out.println("Directory '" + directory + "' deleted successfully");
	}
}
