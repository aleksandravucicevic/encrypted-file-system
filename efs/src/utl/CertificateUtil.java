package utl;

import java.io.*;
import java.util.*;
import java.util.stream.*;
import java.nio.file.*;
import system.EFSystem;

public class CertificateUtil {
	private static boolean revoked = false;
	private static boolean expired = false;
	private static boolean diffCA = false;
	
	public static File clientCertDir = new File(EFSystem.pr.getProperty("CLIENT_CERT_DIR"));
	static {
		if (!clientCertDir.exists()){
			clientCertDir.mkdir();
		}
	}
	
	public static String assignUserCertificate(String username) {
		Path certDir = Path.of(EFSystem.pr.getProperty("CLIENT_CERT_DIR"));
		Path assignedCertsFile = certDir.resolve("assigned_certs.txt");

		// assigning one of the certs to the user
		try(Stream<Path> files = Files.list(certDir)) {
			List<String> assignedCerts = Files.exists(assignedCertsFile) ? Files.readAllLines(assignedCertsFile) : List.of();
			
			for(Path cert: files.toList()) {
				if(cert.toString().endsWith(".crt")) {
					String certName = cert.getFileName().toString();
					String commonName = getCommonName(cert);
					
					// checking if the common name is matching
					if(commonName == null || !commonName.equals(username)) {
						continue;
					}
					
					boolean assigned = assignedCerts.stream().anyMatch(line -> line.endsWith("=" + certName));
					if(!assigned) {
						if(!validateCertificate(certName)) {
		                    System.out.print("Skipping invalid certificate: " + certName);
		                    if(revoked)
		                    	System.out.println(" [reason: revoked]");
		                    else if(diffCA) {
		                    	System.out.println(" [reason: signed by another CA]");
		                    } else if(expired) {
		                    	System.out.println(" [reason: expired]");
		                    } else {
		                    	System.out.println(" [reason: unspecified]");
		                    }
		                    continue;
		                }
						String entry = username + "=" + certName;
						Files.write(assignedCertsFile, List.of(entry), StandardOpenOption.CREATE, StandardOpenOption.APPEND);
						System.out.println("Certificate " + certName + " assigned to user " + username);
						EFSystem.saveUsers();
						return certName;
					}
				}
			}
		} catch(Exception e) {
			e.printStackTrace();
		}
		
		System.out.println("No valid certificate found for user " + username + ". Registration failed.");
		EFSystem.saveUsers();
		return null;
	}
	
	public static boolean validateCertificate(String certName) {
		Path caFilePath = Path.of(EFSystem.pr.getProperty("CA_CERT_PATH"));
		Path crlFilePath = Path.of(EFSystem.pr.getProperty("CRL_PATH"));
		Path userCert = Path.of(EFSystem.pr.getProperty("CLIENT_CERT_DIR")).resolve(certName);
		
		try {
			ProcessBuilder pb = new ProcessBuilder("wsl", "openssl", "verify", "-CAfile", EncryptionUtil.convertToWSLPath(caFilePath), "-crl_check", "-CRLfile", EncryptionUtil.convertToWSLPath(crlFilePath), EncryptionUtil.convertToWSLPath(userCert));
			
			pb.redirectErrorStream(true);
	        Process process = pb.start();
	        
	        String line;
	        StringBuilder outputBuilder = new StringBuilder();
	        try(BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
	            while((line = reader.readLine()) != null) {
	                outputBuilder.append(line).append("\n");
	            }
	        }
	        
	        process.waitFor();
	        String output = outputBuilder.toString().trim().toLowerCase();
	        
	        if(output.contains("revoked")) {
	        	revoked = true;
	        	diffCA=false;
	        	expired=false;
	            return false;
	        } else if(output.contains("unable to get local issuer certificate")) {
	        	diffCA = true;
	        	revoked = false;
	        	expired=false;
	        	return false;
	        } else if(output.contains("expired")) {
	        	expired = true;
	        	revoked = false;
	        	diffCA=false;
	        	return false;
	        } else if(output.contains(" ok")) {
	            return true;
	        } else {
	        	return false;
	        }
		} catch(Exception e) {
			System.out.println();
		}
		
		return false;
	}
	
	private static String getCommonName(Path certPath) {
		try {
			ProcessBuilder pb = new ProcessBuilder("wsl", "openssl", "x509", "-in", EncryptionUtil.convertToWSLPath(certPath), "-noout", "-subject");
			String output = EncryptionUtil.executeProcess(pb).trim();
			
			if(output == null || output.isEmpty()) {
	            throw new RuntimeException("Failed to retrieve certificate subject.");
	        }
			
			if(output.startsWith("subject=")) {
				output = output.substring("subject=".length());
			}
			
			String parts[] = output.split(",");
			for(String part : parts) {
				part = part.trim();
				
				if(part.startsWith("CN")) {
					String cnParts[] = part.split("=");
					if(cnParts.length >= 2) {
						return cnParts[1].trim();
					}
				}
			}
			
		} catch(Exception e) {
			e.printStackTrace();
		}
		
		return null;
	}
}
