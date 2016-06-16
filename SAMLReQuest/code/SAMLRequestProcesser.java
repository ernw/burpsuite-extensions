/**
 * @author Ahmad Abolhadid <bo7adeed@gmail.com>
 */

package burp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.zip.Deflater;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;
import javax.xml.bind.DatatypeConverter;

public class SAMLRequestProcesser
{
	private String httpMethod;

	public String prepareSAML(String input)
	    {
	    	String result;
	    	byte[] decodedSaml;
	    	
	    	decodedSaml= decodeSAML(input);
	        result = new String(decodedSaml);
	        
	        if (this.httpMethod.equals("GET"))
	        {
	        	result = this.inflateSAML(decodedSaml);
	        }
	        return result;
	    }
	    
	    public byte[] decodeSAML(String input)
		{
	    	byte[] base64Dec;
			String urlDec="";

			try
			{
				 urlDec = URLDecoder.decode(input,"UTF-8");
			}
			catch(Exception e)
			{
				e.printStackTrace();
			}
			
			base64Dec = DatatypeConverter.parseBase64Binary(urlDec); 

			return base64Dec;
		}
	    
	    public String inflateSAML(byte[] bytes)
		{
	    	byte[] buf;
	    	int count;
			Inflater decompressor = null;
	        InflaterInputStream decompressorStream = null;
	        ByteArrayOutputStream out = new ByteArrayOutputStream();

	         try 
	         {
	              decompressor = new Inflater(true);
	              decompressorStream = new InflaterInputStream( new ByteArrayInputStream(bytes), decompressor);
	              buf = new byte[1024];
	              
	              while ((count = decompressorStream.read(buf)) != -1) 
	              {
	                   out.write(buf, 0, count);
	              }

	              String outString = out.toString();
	              return outString;
	         }
	         catch(Exception e)
	         {
	        	 e.printStackTrace();
	        	 return "SAMLReQuest: Cannot decompress SAML request!!";
	         }
		}
	  
	    public byte[] injectSAML(byte[] saml,int nowrap)
	    {
	    	byte [] deflatedSAML, encodedSAML;
	    	
   			deflatedSAML = saml;
	    	if (this.httpMethod.equals("GET"))
	    	{
	    		deflatedSAML=compressSAML(new String(saml), nowrap);
	    	}
	    	encodedSAML=encodeSAML(deflatedSAML);
	    	
	    	return encodedSAML;
	    }
	    
	    public byte[] encodeSAML(byte[] saml)
		{
			String base64String, result ="";
			
			base64String = DatatypeConverter.printBase64Binary(saml);
			try
			{
				 result = URLEncoder.encode(base64String, "UTF-8");		 
			}
			catch(Exception e)
			{
				e.printStackTrace();
				System.out.println("Failure encodeSAML");
			}
			
			return result.getBytes();
		}
	    
	    public byte[] compressSAML(String input, int level)
		{
	    	byte[] buffer, samlBytes, inputBytes;
			Deflater deflater;
			
			deflater = new Deflater(level,true);
	   	 	buffer = new byte[1024];
	        samlBytes = null;
	        inputBytes = input.getBytes();
	        deflater.setInput(inputBytes); 
	        try
	        {
	            ByteArrayOutputStream outputStream = new ByteArrayOutputStream(inputBytes.length);   
	            deflater.finish();  
	            while (!deflater.finished()) 
	            {
	            	int count = deflater.deflate(buffer);
	                outputStream.write(buffer, 0, count);  
	            }
	            outputStream.close();
	            samlBytes = outputStream.toByteArray();
	        }
	        catch (IOException e)
	        {
	        	e.printStackTrace();
	        }
			
	        return samlBytes;
		}

		public String getHttpMethod() {
			return this.httpMethod;
		}

		public void setHttpMethod(String httpMethod) {
			this.httpMethod = httpMethod;
		}

}
