package system;

import java.nio.file.*;
import java.util.*;

public class Main {
	static {
		EFSystem.loadUsers();
	}
	public static Scanner scan = new Scanner(System.in);
	private static User currentUser = null;
	
	public static void main(String args[]) {
		System.out.println();
		System.out.println("----------------------------------------");
		System.out.println("WELCOME TO EFS - Encrypted File System!");
		System.out.println("----------------------------------------");
		boolean quit = false;
		while(!quit){
			System.out.println();
			System.out.println("Login [L]     Register [R]     Quit [Q]");
			String input = scan.nextLine();
			
			if("l".equalsIgnoreCase(input)) {
				if(EFSystem.login()) {
					handleUserSession();
				}
			} else if("r".equalsIgnoreCase(input)) {
				if(EFSystem.register()) {
					handleUserSession();
				}
			} else if("q".equalsIgnoreCase(input)) {
				System.out.println("Goodbye!");
				quit = true;
			} else {
				System.out.println("Unsupported action!");
			}
		}
		
		currentUser = null;
		EFSystem.saveUsers();
	}
	
	private static void handleUserSession() {
		EFSManager efsm = new EFSManager(EFSystem.currentUsername);
		currentUser = EFSystem.EFSusers.get(EFSystem.currentUsername);
		
		boolean loggedIn = true;
		while(loggedIn) {
			System.out.println("----------------------------------------");
			System.out.println("Choose an action:");
			System.out.println("List my files				[1]");
			System.out.println("Upload file to my EFS folder		[2]");
			System.out.println("Download file from my EFS folder	[3]");
			System.out.println("List shared files			[4]");
			System.out.println("Upload file to shared folder		[5]");
			System.out.println("Download file from shared folder	[6]");
			System.out.println("Add folder to your EFS folder		[7]");
			System.out.println("Delete folder from your EFS folder	[8]");
			System.out.println("Logout					[9]");
			System.out.println("----------------------------------------");
			
			String choice = scan.nextLine();
			
			try {
				switch(choice) {
				case "1":
					efsm.listUserFiles();
					break;
				case "2":
					System.out.print("Enter path of the file you would like to upload: ");
					String uploadFilePath2 = scan.nextLine();
					System.out.print("Enter destination path (inside your EFS HOME): ");
					String destinationPath2 = scan.nextLine();
					efsm.addFile(uploadFilePath2,destinationPath2);
					break;
				case "3":
					efsm.listUserFiles();
					System.out.println();
					System.out.print("Enter path of the file you would like to download (inside your EFS HOME): ");
					String encryptedFilePath3 = scan.nextLine();
					boolean validPath3 = false;
					String destinationPath3 = null;
					
					while(!validPath3) {
						System.out.print("Enter destination path for the download: ");
						destinationPath3 = scan.nextLine();
						Path destPath3 = Paths.get(destinationPath3).toAbsolutePath().normalize();
						
						if(destPath3.startsWith(EFSManager.PROHIBITED)) {
							System.out.println("You cannot download files into the EFS system directory. Choose another destination [y/n]");
							String choice3 = scan.nextLine();
							if("y".equalsIgnoreCase(choice3)) {
								continue;
							} else {
								System.out.println("Download cancelled.");
								break;
							}
						} else {
							validPath3 = true;
						}
					}
					
					if(validPath3) {
						efsm.downloadFile(encryptedFilePath3,destinationPath3,currentUser.getPrivateKeyPath().toString());
					}
					break;
				case "4":
					efsm.listSharedFiles();
					break;
				case "5":
					System.out.print("Enter path of the file you would like to upload to the SHARED: ");
					String uploadFilePath5 = scan.nextLine();
					System.out.print("Enter recipient's username: ");
					String recipient = scan.nextLine();
					efsm.addFileToShared(uploadFilePath5,recipient);
					break;
				case "6":
					efsm.listSharedFiles();
					System.out.println();
					System.out.print("Enter path of the file you would like to download (inside EFS SHARED): ");
					String encryptedFilePath6 = scan.nextLine();
					boolean validPath6 = false;
					String destinationPath6 = null;
					
					while(!validPath6) {
						System.out.print("Enter destination path for the download: ");
						destinationPath6 = scan.nextLine();
						Path destPath6 = Paths.get(destinationPath6).toAbsolutePath().normalize();
						
						if(destPath6.startsWith(EFSManager.PROHIBITED)) {
							System.out.println("You cannot download files into the EFS system directory. Choose another destination [y/n]");
							String choice6 = scan.nextLine();
							if("y".equalsIgnoreCase(choice6)) {
								continue;
							} else {
								System.out.println("Download cancelled.");
								break;
							}
						} else {
							validPath6 = true;
						}
					}
					
					if(validPath6) {
						efsm.downloadFileFromShared(encryptedFilePath6,destinationPath6);
					}
					
					break;
				case "7":
					System.out.print("Enter the path of the folder in which you'd like to add the new folder (inside your EFS HOME): ");
					String destDir = scan.nextLine();
					System.out.print("Enter name of the new folder: ");
					String newDir = scan.nextLine();
					efsm.createDirectory(destDir,newDir);
					break;
				case "8":
					System.out.print("Enter the path of the folder in which you'd like to delete (inside your EFS HOME): ");
					String targetDir = scan.nextLine();
					efsm.deleteDirectory(targetDir);
					break;
				case "9":
					System.out.println("Logging out...");
					loggedIn = false;
					break;
				default:
					System.out.println("Invalid option...");
					break;
				}
			} catch(Exception e) {
				System.err.println("Error: " + e.getMessage());
			}
		}
	}
}
