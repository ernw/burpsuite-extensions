/**
 * @author Ahmad Abolhadid <bo7adeed@gmail.com>
 */

package burp;

public class IntruderProcessor implements IHttpListener
{
	private IExtensionHelpers helpers;
	private SAMLRequestProcesser proc;
	
	public IntruderProcessor(IExtensionHelpers helpers) 
	{
		this.helpers = helpers;
		this.proc = new SAMLRequestProcesser();
	}


	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse theMsg) 
	{
		byte[] finalSAML;
		String reqStr,samlPar, finalSAMLStr,finalMsg;
		
		if (messageIsRequest && toolFlag == IBurpExtenderCallbacks.TOOL_INTRUDER)
		{
			byte[] req = theMsg.getRequest();
			String httpMethod = this.helpers.analyzeRequest(theMsg).getMethod();
			this.proc.setHttpMethod(httpMethod);		
			reqStr = new String(req);
			samlPar = this.getUncodedSAMLPar(reqStr);
			finalSAML=this.proc.injectSAML(samlPar.getBytes(),5);
			finalSAMLStr = new String(finalSAML);
			finalMsg = reqStr.replaceFirst(samlPar, finalSAMLStr);
			theMsg.setRequest(finalMsg.getBytes());
		}
		
	}
	
	private String getUncodedSAMLPar(String request)
	{
		int samlStart, samlEnd;
		String samlPar;
		
		samlStart= request.indexOf("<samlp:AuthnRequest");
		samlEnd= request.indexOf("</samlp:AuthnRequest>");
		samlPar = request.substring(samlStart, samlEnd+21);
		
		return samlPar;
	}

	

}
