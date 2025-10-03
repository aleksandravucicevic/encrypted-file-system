package system;

import java.util.*;
import java.io.*;
import java.nio.file.*;
import utl.*;

public class EFSystem {
	public static Scanner scan = new Scanner(System.in);
	private static String propertiesFile = "src/utl/paths.properties";
	public static PropertyReader pr = new PropertyReader(propertiesFile);
	public static Path allUsersFilePath = Path.of(pr.getProperty("USERS_DIR") + "users.dat");
	public static Map<String, User> EFSusers = new HashMap<>();
	public static String currentUsername = "";
	
	// register
	public static boolean register() {		
		System.out.print("Enter username you would like to use: ");
		String username = scan.nextLine();
		
		// username already in use
		while(checkIfUsernameExists(username)){
			System.out.print("Username is already in use! Would you like to try again? [y/n] ");
			String input = scan.nextLine();
			if("y".equalsIgnoreCase(input)){
				System.out.print("Username: ");
				username = scan.nextLine();
			} else {
				System.out.println("Goodbye!");
				return false;
			}
		}
		
		System.out.print("Enter password: ");
		String enteredPassword = scan.nextLine();
		String hashPass = EncryptionUtil.hashPassword(enteredPassword);
		
		// digital certificate and keys
		String certName = CertificateUtil.assignUserCertificate(username);
		if(certName == null) {
			return false;
		}
		
		Path certPath = Path.of(pr.getProperty("CLIENT_CERT_DIR"), certName);
		Path keyPath = Path.of(pr.getProperty("CLIENT_KEY_DIR"), certName.replace(".crt", ".key"));

		User newUser = new User(username,hashPass,certPath,keyPath);
		EFSusers = loadUsers();
		EFSusers.put(username, newUser);
		newUser.setPublicKeyPath();
		saveUsers();
		
		System.out.println("User " + username + " registered successfully!");
		currentUsername = username;
		return true;
	}
	
	// login
	public static boolean login() {
		String username = "";
		boolean userok = false;
		EFSusers = loadUsers();
		
		while(!userok) {
			System.out.print("Username: ");
			username = scan.nextLine();
			
			// username doesn't exist
			if(!checkIfUsernameExists(username)) {
				System.out.print("Username doesn't exist! Would you like to register? [y/n] ");
				String input = scan.nextLine().trim();
				if("y".equalsIgnoreCase(input)) {
					return register();
				}
				
				System.out.print("Would you like to try logging in again? [y/n] ");
				String in = scan.nextLine().trim();
				if(!"y".equalsIgnoreCase(in)) {
					System.out.println("Goodbye!");
					return false;
				}
				
			} else {
				userok = true;
			}
		}
		
		// checking for certificate
		User user = EFSusers.get(username);
		Path certPath = user.getDigitalCert();
		if(!Files.exists(certPath)) {
			System.out.println("Error: client certificate not found!");
			return false;
		}
		
		// certificate validation
		if(!CertificateUtil.validateCertificate(certPath.toString())) {
			System.out.println("Certificate isn't valid!");
			return false;
		}
		
		// checking if password is correct
		int tmp=0;
		while(tmp<3) {
			System.out.print("Password: ");
			if(verifyPassword(username, scan.nextLine())) {
				System.out.println("Login successful!");
				currentUsername = username;
				return true;
			} else {
				System.out.println("Incorrect password! Try again...");
				tmp++;
			}
		}
		
		System.out.println("Too many failed attempts. Login failed.");
		return false;
		
	}
	
	// -------------------------------------------------------------
	// private methods:
	
	private static boolean checkIfUsernameExists(String username) {
		if(EFSusers.containsKey(username))
			return true;
		else
			return false;
	}
	
	private static boolean verifyPassword(String username, String password) {
	 	User user = EFSusers.get(username);
	 	String userPass = user.getPasswordHash();
	 	if(userPass==null)
	 		return false;
	 	
	 	String salt = userPass.split("\\$")[2];
	 	String hashedPassword = EncryptionUtil.hashPasswordWithSalt(password,salt);
        return hashedPassword.equals(userPass);
    }
	
	public static Path getPublicKey(String username) throws Exception{
		User user = EFSusers.get(username);
		if(user == null) {
			return null;
		}
		Path certPath = user.getDigitalCert();
		
		String certPathStr = EncryptionUtil.convertToWSLPath(certPath).toString();		
		String certName = certPath.getFileName().toString().replace(".crt", "_public.key");
		
		ProcessBuilder pb = new ProcessBuilder("wsl", "openssl", "x509", "-in", certPathStr, "-pubkey", "-noout");
		pb.redirectErrorStream(true);
		Process process = pb.start();
		
		try(BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))){
			StringBuilder publicKey = new StringBuilder();
			String line;
			while((line = reader.readLine()) != null) {
				publicKey.append(line).append("\n");
			}
			
			int exitCode = process.waitFor();
			if(exitCode != 0) {
				throw new RuntimeException("OpenSSL process failed with exit code " + exitCode + ". Output:\n" + publicKey);
			}
			
			Path publicKeyDir = Path.of(pr.getProperty("PUBLIC_CLIENT_KEY_DIR"));
			if(!Files.exists(publicKeyDir)) {
	            Files.createDirectories(publicKeyDir);
	        }
			
			Path publicKeyPath = publicKeyDir.resolve(certName);
			Files.write(publicKeyPath, publicKey.toString().getBytes(), StandardOpenOption.CREATE, StandardOpenOption.WRITE);
			
			return publicKeyPath;
		}
	}
	
	public static void saveUsers() {
		try {
			Files.createDirectories(allUsersFilePath.getParent());
		    
			try (ObjectOutputStream oos = new ObjectOutputStream(Files.newOutputStream(allUsersFilePath))) {
		    	oos.writeObject(EFSusers);
		    }
			
		} catch (IOException e) {
			System.err.println("Error saving users...");
			e.printStackTrace();
		}
	}
	
	@SuppressWarnings("unchecked")
	public static Map<String, User> loadUsers() {
		try {
		    if(!Files.exists(allUsersFilePath)) {
		    	Files.createFile(allUsersFilePath);
		        return new HashMap<>();
		    }
	
		    try(ObjectInputStream ois = new ObjectInputStream(Files.newInputStream(allUsersFilePath))) {
		        return (Map<String, User>) ois.readObject();
		    }
		} catch(Exception e) {
			return new HashMap<>();
		}
	}
}
