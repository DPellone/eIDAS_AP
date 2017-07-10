package net.polito.pellone;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.saml2.core.RequestAbstractType;

import net.shibboleth.idp.profile.context.RelyingPartyContext;
import net.shibboleth.idp.profile.interceptor.ProfileInterceptorFlowDescriptor;
import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.context.AttributeContext;


/**
 * 
 * 
 * @author Daniele Pellone
 *
 */
public class EidasReleaseAttributes extends ProfileInterceptorFlowDescriptor {
	
	Set<String> requestedAttributes = null;
	
	public EidasReleaseAttributes() {
			super();
			this.setId("EidasReleaseAttributes");
		}

	@SuppressWarnings("rawtypes")
	@Override
	public boolean apply(ProfileRequestContext input){
		
			// Prima parte: ottenimento della lista di attributi richiesti
		
		Object messageObj = input.getInboundMessageContext().getMessage();
		// Controllo che il messaggio sia una richiesta SAML
		if(messageObj instanceof RequestAbstractType){
			RequestAbstractType message = (RequestAbstractType)messageObj;
			// Ottenimento della lista di estensioni
			List<XMLObject> extensions = message.getExtensions().getOrderedChildren();
			for (XMLObject extension : extensions) {
				// Verifica dell'esistenza dell'estensione "RequestedAttributes"
				if(extension.getElementQName().getLocalPart().equals("RequestedAttributes")){
					requestedAttributes = new TreeSet<String>();
					for (XMLObject requestedAttribute : extension.getOrderedChildren()) {
						// Copia della lista di attributi richiesti
						requestedAttributes.add(requestedAttribute.getDOM().getAttribute("FriendlyName"));
					}
					break;
				}
			}
		}
		
			// Seconda parte: aggiunta agli attributi filtrati di quelli richiesti
		
		if(requestedAttributes != null){
			// Ottenimento dei contesti necessari
			RelyingPartyContext rpContext = input.getSubcontext(RelyingPartyContext.class);
			if(rpContext != null){
				AttributeContext afContext = rpContext.getSubcontext(AttributeContext.class);
				if(afContext != null){
					// Ottenimento delle liste di attributi filtrati e non
					Collection<IdPAttribute> unfilteredAttributes = afContext.getUnfilteredIdPAttributes().values(),
							filteredAttributes = new ArrayList<IdPAttribute>();
					filteredAttributes.addAll(afContext.getIdPAttributes().values());
					Map<String, IdPAttribute> filteredAttributesMap = afContext.getIdPAttributes();
					// Se un attributo richiesto è stato scartato viene inserito tra quelli filtrati
					for (IdPAttribute unfilteredAttribute : unfilteredAttributes) {
						if(!filteredAttributesMap.containsKey(unfilteredAttribute.getId()) && requestedAttributes.contains(unfilteredAttribute.getId()))
							filteredAttributes.add(unfilteredAttribute);
					}
					// Sostituzione della lista di attributi da rilasciare con quella appena costruita
					afContext.setIdPAttributes(filteredAttributes);
				}
			}
			// Pulitura della lista
			requestedAttributes = null;
		}

		return true;
	}
}
