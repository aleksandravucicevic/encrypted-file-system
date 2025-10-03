package utl;

import java.io.*;
import java.util.*;

public class PropertyReader {
	protected Properties properties;
	
	public PropertyReader(String propertiesFile){
		properties = new Properties();
		try(InputStream input = new FileInputStream(propertiesFile)){
			properties.load(input);
		} catch(IOException e){
			e.printStackTrace();
		}
	}
	
	public String getProperty(String key){
		return properties.getProperty(key);
	}
}
