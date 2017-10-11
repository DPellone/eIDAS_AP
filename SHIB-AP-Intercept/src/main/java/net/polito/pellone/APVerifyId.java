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
		
		Logger log = LoggerFactory.getLogger(APVerifyId.class);
		String requestedId, authenticatedId;
		
		Object messageObj = input.getInboundMessageContext().getMessage();
		if(messageObj instanceof AuthnRequest){
			AuthnRequest message = (AuthnRequest)messageObj;
			requestedId = message.getSubject().getNameID().getValue();
		} else
			return false;
		
		authenticatedId = input.getSubcontext(SubjectContext.class).getPrincipalName();
		
		log.error("req: " + requestedId);
		log.error("auth: " + authenticatedId);
		if(authenticatedId.equals(requestedId))
			return true;
		else
			return false;
	}
	
}
