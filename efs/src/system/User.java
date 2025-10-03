package system;

import java.io.*;
import java.nio.file.*;

public class User implements Serializable{
	private static final long serialVersionUID = 1L;
	private String username;
	private String passwordHash;
	private transient String homeDir = EFSystem.pr.getProperty("ROOT_BASE");
	private transient Path digitalCertPath;
	private transient Path privateKeyPath;
	private transient Path publicKeyPath;
	
	private String certPathStr;
	private String privKeyPathStr;
	private String pubKeyPathStr;
	
	public User(String username, String passwordHash, Path digitalCertPath, Path privateKeyPath) {
		this.username = username;
		this.homeDir += this.username;
		this.passwordHash = passwordHash;
		this.digitalCertPath = digitalCertPath;
		this.privateKeyPath = privateKeyPath;
		
		this.certPathStr = this.digitalCertPath.toString();
		this.privKeyPathStr = this.privateKeyPath.toString();
	}
	
	public String getUsername() {
		return username;
	}
	
	public String getPasswordHash() {
		return passwordHash;
	}
	
	public String getHomeDir() {
		return homeDir;
	}
	
	public Path getDigitalCert() {
		return digitalCertPath;
	}
	
	public Path getPrivateKeyPath() {
		return privateKeyPath;
	}
	
	public Path getPublicKeyPath() {
		return publicKeyPath;
	}
	
	public void setPublicKeyPath() {
		try {
			this.publicKeyPath = EFSystem.getPublicKey(username);
		} catch(Exception e) {
			e.printStackTrace();
		}
	}
	
	private void writeObject(ObjectOutputStream oos) throws IOException {
	    oos.defaultWriteObject();
	    
	    oos.writeObject(digitalCertPath != null ? digitalCertPath.toString() : null);
	    oos.writeObject(privateKeyPath != null ? privateKeyPath.toString() : null);
	    oos.writeObject(publicKeyPath != null ? publicKeyPath.toString() : null);
	}
	
	private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException{
		ois.defaultReadObject();
		
		certPathStr = (String) ois.readObject();
		privKeyPathStr = (String) ois.readObject();
		pubKeyPathStr = (String) ois.readObject();
		
		digitalCertPath = certPathStr != null ? Paths.get(certPathStr) : null;
		privateKeyPath = privKeyPathStr != null ? Paths.get(privKeyPathStr) : null;
		publicKeyPath = pubKeyPathStr != null ? Paths.get(pubKeyPathStr) : null;
		
		if(homeDir == null || homeDir.isEmpty()) {
			homeDir = EFSystem.pr.getProperty("ROOT_BASE") + username;
		}
	}
}
