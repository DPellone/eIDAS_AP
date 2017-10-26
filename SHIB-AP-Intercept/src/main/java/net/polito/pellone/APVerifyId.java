package net.polito.pellone;

import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.shibboleth.idp.authn.context.SubjectContext;
import net.shibboleth.idp.profile.interceptor.ProfileInterceptorFlowDescriptor;


/**
 * 
 * 
 * @author Daniele Pellone
 *
 */
public class APVerifyId extends ProfileInterceptorFlowDescriptor {
	
	
	public APVerifyId() {
			super();
			this.setId("APVerifyId");
		}

	@SuppressWarnings("rawtypes")
	@Override
	public boolean apply(ProfileRequestContext input){
		
		String requestedId, authenticatedId;
		
		try {
			Object messageObj = input.getInboundMessageContext().getMessage();
			if(messageObj instanceof AuthnRequest){
				AuthnRequest message = (AuthnRequest)messageObj;
				requestedId = message.getSubject().getNameID().getValue();
			} else
				return false;
			
			authenticatedId = input.getSubcontext(SubjectContext.class).getPrincipalName();
			
			return authenticatedId.equals(requestedId);
			
		} catch (NullPointerException e) {
			return false;
		}
	}
	
}
