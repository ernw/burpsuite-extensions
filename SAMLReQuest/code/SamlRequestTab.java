/**
 * @author Ahmad Abolhadid <bo7adeed@gmail.com>
 */

package burp;

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.Deflater;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JPanel;


import org.apache.commons.codec.binary.Base64;

public class SamlRequestTab implements IMessageEditorTab
{
    private boolean editable;
    private ITextEditor txtInput;
    private JButton sendToInt;
    private byte[] currentMessage;
    private String requestMethod;
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private SAMLRequestProcesser processor;
    private IRequestInfo requestInfo;

    public SamlRequestTab(IMessageEditorController controller, boolean editable,IBurpExtenderCallbacks callbacks)
    {
    	this.callbacks = callbacks;
    	this.helpers = this.callbacks.getHelpers();    	
        this.editable = editable;
        this.processor = new SAMLRequestProcesser();
        this.txtInput = callbacks.createTextEditor();
        this.txtInput.setEditable(editable); 
        
    }

    @Override
    public String getTabCaption()
    {
        return "SAML ReQuest";
    }

    @Override
    public Component getUiComponent()
    {
    	JPanel panel;
    	BoxLayout layout;
    	panel= new JPanel();
    	layout = new BoxLayout(panel, BoxLayout.Y_AXIS);
		panel.setLayout(layout);
		this.sendToInt = new JButton("Send Decoded Request to Intruder");
    	
		this.sendToInt.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				byte methodByte;		
				String destHost, undecodedSAML;
				byte[] undecodedReq;
				
				List<String> headerz = requestInfo.getHeaders();
				
				if (requestInfo.getMethod().equals("GET"))
				{
					methodByte = IParameter.PARAM_URL;
				}
				else
				{
					methodByte = IParameter.PARAM_BODY;
				}
				
				destHost = headerz.get(1).substring(6);
				undecodedSAML = new String (txtInput.getText());
				undecodedReq = helpers.updateParameter(currentMessage, helpers.buildParameter("SAMLRequest", undecodedSAML, methodByte));
				callbacks.sendToIntruder(destHost, 443, true, undecodedReq);
				
			}
    		
    	});
		
		panel.add(this.txtInput.getComponent());
    	panel.add(this.sendToInt);
    	return panel;

    }

    @Override
    public boolean isEnabled(byte[] content, boolean isRequest)
    {
        return isRequest && null != this.helpers.getRequestParameter(content, "SAMLRequest");
    }

     
    @Override
    public void setMessage(byte[] content, boolean isRequest)
    {
    	IParameter parameter;
    	String readySAML;
        if (content == null)
        {
            this.txtInput.setText(null);
            this.txtInput.setEditable(false);
        }
        else
        {
            parameter = this.helpers.getRequestParameter(content, "SAMLRequest");
            this.requestInfo = this.helpers.analyzeRequest(content);
            this.requestMethod = this.requestInfo.getMethod();           
            this.processor.setHttpMethod(this.requestMethod);
            readySAML = this.processor.prepareSAML(parameter.getValue());
  
            this.txtInput.setText(readySAML.getBytes());
            this.txtInput.setEditable(editable);
        }
        
        this.currentMessage = content;
    }
    
    
    @Override
    public byte[] getMessage()
    {
    	byte methodByte;
    	byte[] text;
    	text = txtInput.getText();       	 
    	byte[] finalSAML=this.processor.injectSAML(text,5);
    	String encSAMLSTring = new String(finalSAML);
    	
    	if (this.requestMethod.equals("GET"))
		{
			methodByte = IParameter.PARAM_URL;
		}
		else
		{
			methodByte = IParameter.PARAM_BODY;
		}
    	
    	
    	return helpers.updateParameter(currentMessage, helpers.buildParameter("SAMLRequest", encSAMLSTring, methodByte)); 

    }
    
    @Override
    public boolean isModified()
    {
        return txtInput.isTextModified();
    }

    @Override
    public byte[] getSelectedData()
    {
        return txtInput.getSelectedText();
    }
    
}

