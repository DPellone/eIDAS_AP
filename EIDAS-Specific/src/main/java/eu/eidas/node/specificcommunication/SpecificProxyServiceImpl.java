package eu.eidas.node.specificcommunication;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.annotation.Nonnull;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import eu.eidas.auth.commons.EIDASStatusCode;
import eu.eidas.auth.commons.EIDASUtil;
import eu.eidas.auth.commons.EidasErrorKey;
import eu.eidas.auth.commons.EidasErrors;
import eu.eidas.auth.commons.EidasParameterKeys;
import eu.eidas.auth.commons.EidasStringUtil;
import eu.eidas.auth.commons.IncomingRequest;
import eu.eidas.auth.commons.attribute.AttributeDefinition;
import eu.eidas.auth.commons.attribute.ImmutableAttributeMap;
import eu.eidas.auth.commons.attribute.PersonType;
import eu.eidas.auth.commons.light.ILightRequest;
import eu.eidas.auth.commons.light.ILightResponse;
import eu.eidas.auth.commons.light.impl.LightResponse;
import eu.eidas.auth.commons.protocol.IAuthenticationRequest;
import eu.eidas.auth.commons.protocol.IAuthenticationResponse;
import eu.eidas.auth.commons.protocol.impl.AuthenticationResponse;
import eu.eidas.auth.commons.protocol.impl.EidasSamlBinding;
import eu.eidas.auth.commons.tx.AuthenticationExchange;
import eu.eidas.auth.commons.tx.CorrelationMap;
import eu.eidas.auth.commons.tx.StoredLightRequest;
import eu.eidas.auth.commons.validation.NormalParameterValidator;
import eu.eidas.auth.engine.SamlEngine;
import eu.eidas.auth.engine.xml.opensaml.SAMLEngineUtils;
import eu.eidas.auth.specific.IAUService;
import eu.eidas.node.CitizenAuthenticationBean;
import eu.eidas.node.SpecificIdPBean;
import eu.eidas.node.SpecificParameterNames;
import eu.eidas.node.SpecificViewNames;
import eu.eidas.node.auth.specific.SpecificEidasService;
import eu.eidas.node.specificcommunication.exception.SpecificException;
import eu.eidas.node.specificcommunication.protocol.IResponseCallbackHandler;

import static eu.eidas.auth.commons.EidasParameterKeys.EIDAS_SERVICE_CALLBACK;
import static eu.eidas.auth.engine.core.SAMLExtensionFormat.EIDAS_FORMAT_NAME;
import static eu.eidas.node.SpecificServletHelper.getHttpRequestAttributesHeaders;
import static eu.eidas.node.SpecificServletHelper.getHttpRequestParameters;

/**
 * SpecificProxyServiceImpl: provides a sample implementation of the specific interface {@link ISpecificProxyService}
 * For the request: it creates the message bytes to send to IdP for authentication For the response: it validates the
 * received IdP specific response and builds the LightResponse
 *
 * @since 1.1
 */
public class SpecificProxyServiceImpl implements ISpecificProxyService {

    private static final Logger LOGGER = LoggerFactory.getLogger(SpecificProxyServiceImpl.class);

    private CitizenAuthenticationBean citizenAuthentication;

    private boolean signResponseAssertion;

    private SpecificIdPBean specificIdPResponse;
    
    // --- MOD ---
    // Lista delle risposte per cui mancano degli attributi
    static private Map<String, IAuthenticationResponse> incompleteResponses = Collections.synchronizedMap(new HashMap<String, IAuthenticationResponse>());
    // Lista dei mapping richiesta-AP
    static private Map<String, String> requestAttributeProviderCorrelationMap = Collections.synchronizedMap(new HashMap<String, String>());
    
    public CitizenAuthenticationBean getCitizenAuthentication() {
        return citizenAuthentication;
    }

    public void setCitizenAuthentication(CitizenAuthenticationBean citizenAuthentication) {
        this.citizenAuthentication = citizenAuthentication;
    }

    public boolean isSignResponseAssertion() {
        return signResponseAssertion;
    }

    public void setSignResponseAssertion(boolean signResponseAssertion) {
        this.signResponseAssertion = signResponseAssertion;
    }

    public SpecificIdPBean getSpecificIdPResponse() {
        return specificIdPResponse;
    }

    public void setSpecificIdPResponse(SpecificIdPBean specificIdPResponse) {
        this.specificIdPResponse = specificIdPResponse;
    }

    public Map<String, IAuthenticationResponse> getIncompleteResponses() {
    	return incompleteResponses;
    }
    
    public void setIncompleteResponses(Map<String, IAuthenticationResponse> incompleteResponses) {
    	this.incompleteResponses = incompleteResponses;
    }
    
    @Override
    public void sendRequest(@Nonnull ILightRequest lightRequest,
                            @Nonnull HttpServletRequest httpServletRequest,
                            @Nonnull HttpServletResponse httpServletResponse) throws SpecificException {

        try {
            // build parameter list
            Map<String, Object> parameters = getHttpRequestParameters(httpServletRequest);

            IAUService specificService = citizenAuthentication.getSpecAuthenticationNode();

            ImmutableAttributeMap attrMap = lightRequest.getRequestedAttributes();

            if (citizenAuthentication.isExternalAuth()) {

                LOGGER.trace("external-authentication");

                NormalParameterValidator.paramName(EidasParameterKeys.IDP_URL)
                        .paramValue(citizenAuthentication.getIdpUrl())
                        .validate();
                handleStorkAssertionConsumerUrl(parameters, specificService);

                parameters.put(EidasParameterKeys.IDP_URL.toString(), citizenAuthentication.getIdpUrl());

                parameters.put(EidasParameterKeys.CITIZEN_COUNTRY_CODE.toString(),
                               lightRequest.getCitizenCountryCode());
                parameters.put(EidasParameterKeys.SERVICE_PROVIDER_NAME.toString(), lightRequest.getProviderName());
                parameters.put(EidasParameterKeys.CITIZEN_IP_ADDRESS.toString(),
                               IncomingRequest.getRemoteAddress(httpServletRequest));

                httpServletRequest.setAttribute(EidasParameterKeys.BINDING.toString(), EidasSamlBinding.POST.getName());

                parameters.put(EidasParameterKeys.EIDAS_SERVICE_LOA.toString(), lightRequest.getLevelOfAssurance());
                parameters.put(EidasParameterKeys.EIDAS_NAMEID_FORMAT.toString(), lightRequest.getNameIdFormat());

                parameters.put(EidasParameterKeys.SERVICE_PROVIDER_TYPE.toString(), lightRequest.getSpType());
                
                byte[] samlTokenBytes = specificService.prepareCitizenAuthentication(lightRequest, attrMap, parameters,
                                                                                     getHttpRequestAttributesHeaders(
                                                                                             httpServletRequest));

                // --- MOD ---
                // Memorizzazione AP associato alla richiesta
                requestAttributeProviderCorrelationMap.put((String)parameters.get("EidasID"), (String)parameters.get("__apSelector"));

                // used by jsp
                String samlToken = EidasStringUtil.encodeToBase64(samlTokenBytes);

                httpServletRequest.setAttribute(SpecificParameterNames.SAML_TOKEN.toString(), samlToken);
                httpServletRequest.setAttribute(SpecificParameterNames.IDP_URL.toString(),
                                                citizenAuthentication.getIdpUrl());
                httpServletRequest.setAttribute(EidasParameterKeys.REQUEST_FORMAT.toString(), EIDAS_FORMAT_NAME);

            } else {
                throw new SpecificException("internal-authentication not implemented");
            }
            //redirecting to IdP
            String encodedURL = httpServletResponse.encodeURL(SpecificViewNames.IDP_REDIRECT.toString());
            RequestDispatcher dispatcher = httpServletRequest.getRequestDispatcher(encodedURL);
            dispatcher.forward(httpServletRequest, httpServletResponse);

        } catch (ServletException | IOException e) {
            LOGGER.error("Error converting the LightRequest to the specific protocol");
            throw new SpecificException(e);
        }
    }

    @Override
    public ILightResponse processResponse(@Nonnull HttpServletRequest httpServletRequest,
                                          @Nonnull HttpServletResponse httpServletResponse) throws SpecificException {

        String samlResponse = getSamlResponse(httpServletRequest);

        IAUService specificService = specificIdPResponse.getSpecificNode();

        AuthenticationExchange authenticationExchange =
                specificService.processAuthenticationResponse(EidasStringUtil.decodeBytesFromBase64(samlResponse));

        IAuthenticationResponse specificResponse = authenticationExchange.getConnectorResponse();

        IAuthenticationRequest specificAuthnRequest = authenticationExchange.getStoredRequest().getRequest();
        StoredLightRequest proxyServiceRequest = getStoredLightRequest(specificService, specificResponse.getInResponseToId());

        httpServletRequest.removeAttribute(EidasParameterKeys.ATTRIBUTE_LIST.toString());

        IAuthenticationResponse authenticationResponse;

        if (!EIDASStatusCode.SUCCESS_URI.toString().equals(specificResponse.getStatusCode())) {
            String statusCode = specificResponse.getStatusCode();
            LOGGER.debug("Message from IdP with status code: " + statusCode);

            ILightRequest proxyServiceAuthnRequest = proxyServiceRequest.getRequest();
            authenticationResponse = AuthenticationResponse.builder(specificResponse)
                    .failure(true)
                    .inResponseTo(proxyServiceAuthnRequest.getId())
                    .build();

        } else {
            httpServletRequest.setAttribute(EidasParameterKeys.EIDAS_SERVICE_LOA.toString(),
                                            specificResponse.getLevelOfAssurance());

            // --- MOD ---
            ImmutableAttributeMap requestedAttributes = specificAuthnRequest.getRequestedAttributes();
            boolean partialResponse = incompleteResponses.containsKey(specificResponse.getInResponseToId());

            if (!partialResponse && !isAttributeListValid(specificService, requestedAttributes, specificResponse.getAttributes())) {

                String errorCode = EidasErrors.get(EidasErrorKey.INVALID_ATTRIBUTE_LIST.errorCode());
                String errorMessage = EidasErrors.get(EidasErrorKey.INVALID_ATTRIBUTE_LIST.errorMessage());

                ILightRequest proxyServiceAuthnRequest = proxyServiceRequest.getRequest();

                authenticationResponse = AuthenticationResponse.builder(specificResponse)
                        .failure(true)
                        .statusCode(errorCode)
                        .statusMessage(errorMessage)
                        .inResponseTo(proxyServiceAuthnRequest.getId())
                        .build();

            } else { // --- MOD ---
            	// La risposta di authN è valida, bisogna controllare se sono presenti tutti gli attributi richiesti
            	ImmutableAttributeMap gatheredAttributes;
            	if(partialResponse)
            		gatheredAttributes = ImmutableAttributeMap.builder()
            		.putAll(specificResponse.getAttributes())
            		.putAll(incompleteResponses.get(specificResponse.getInResponseToId()).getAttributes()).build();
            	else
            		gatheredAttributes = ImmutableAttributeMap.builder()
            		.putAll(specificResponse.getAttributes()).build();
            	
            	List<AttributeDefinition<?>> missingAttributes = getMissingAttributes(requestedAttributes, gatheredAttributes);
            	
            	if(missingAttributes == null){ // Successo: tutti gli attributi sono stati recuperati
            		if(partialResponse){
		                ILightRequest proxyServiceAuthnRequest = proxyServiceRequest.getRequest();
		                authenticationResponse = AuthenticationResponse.builder(incompleteResponses.remove(specificResponse.getInResponseToId()))
		                		.attributes(gatheredAttributes)
		                        .inResponseTo(proxyServiceAuthnRequest.getId())
		                        .build();
            		} else {
            			ILightRequest proxyServiceAuthnRequest = proxyServiceRequest.getRequest();
		                authenticationResponse = AuthenticationResponse.builder(specificResponse)
		                        .inResponseTo(proxyServiceAuthnRequest.getId())
		                        .build();
            		}
                
            	} else {// Attributi mancanti
            		
            		String message = "Attributi mancanti";
            		try {
            			String APid = requestAttributeProviderCorrelationMap.get(specificResponse.getInResponseToId());
						if(APid == null || APid == "null"){
							ILightRequest proxyServiceAuthnRequest = proxyServiceRequest.getRequest();
			                authenticationResponse = AuthenticationResponse.builder(specificResponse)
			                        .inResponseTo(proxyServiceAuthnRequest.getId())
			                        .build();
							specificService.getProxyServiceRequestCorrelationMap().remove(specificAuthnRequest.getId());
							specificService.getSpecificIdpRequestCorrelationMap().remove(specificResponse.getInResponseToId());
							requestAttributeProviderCorrelationMap.remove(specificResponse.getInResponseToId());
							return LightResponse.builder(authenticationResponse).build();
						}
						
						// Preparazione richiesta WebService
						KeyStore ks = KeyStore.getInstance("JKS");
			    		FileInputStream fis = new FileInputStream(((SpecificEidasService)specificService).getServiceProperties().getProperty("webservice.keystore"));
			    		ks.load(fis, ((SpecificEidasService)specificService).getServiceProperties().getProperty("webservice.keystore.passw").toCharArray());
			    		
			    		KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
			    		kmf.init(ks, ((SpecificEidasService)specificService).getServiceProperties().getProperty("webservice.keystore.passw").toCharArray());
			    		TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
			    		tmf.init(ks);
			    		
			    		SSLContext sc = SSLContext.getInstance("TLS");
			    		sc.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
			    		
						HttpsURLConnection webServiceRequest = (HttpsURLConnection) new URL(((SpecificEidasService)specificService).getServiceProperties().getProperty("webservice.mappingURL") + APid).openConnection();
						webServiceRequest.setSSLSocketFactory(sc.getSocketFactory());
						
						// Richiesta al WebService per le info sull'AP
						if(webServiceRequest.getResponseCode() != 200){
							authenticationResponse = AuthenticationResponse.builder(specificResponse)
		            				.failure(true)
		            				.statusCode(EidasErrors.get(EidasErrorKey.INVALID_ATTRIBUTE_LIST.errorCode()))
		            				.statusMessage(String.valueOf(webServiceRequest.getResponseCode()))
		            				.inResponseTo(proxyServiceRequest.getRequest().getId())
		            				.build();
							specificService.getProxyServiceRequestCorrelationMap().remove(specificAuthnRequest.getId());
							specificService.getSpecificIdpRequestCorrelationMap().remove(specificResponse.getInResponseToId());
							requestAttributeProviderCorrelationMap.remove(specificResponse.getInResponseToId());
							return LightResponse.builder(authenticationResponse).build();
						}
						
						// Parsing delle informazioni
						ObjectMapper parser = new ObjectMapper();
						JsonNode APInfo = parser.readTree(webServiceRequest.getInputStream());
						
						String apMetadataUrl = APInfo.get("url").asText();
						
						// Costruzione dell'ID utente
						List<StringToken> syntax = parser.readValue(APInfo.get("token").traverse(), new TypeReference<List<StringToken>>(){});
						String newID = IDBuilder.getID(syntax, specificResponse.getAttributes());
						
						//Costruzione risposta per il Connector incompleta
						String requestId = SAMLEngineUtils.generateNCName();
						authenticationResponse = AuthenticationResponse.builder(specificResponse)
		                        .inResponseTo(proxyServiceRequest.getRequest().getId())
		                        .build();
						
						// Memorizzazione risposta incompleta e sostituzione dei mapping
						incompleteResponses.put(requestId, authenticationResponse);
						requestAttributeProviderCorrelationMap.remove(specificResponse.getInResponseToId());
						specificService.getProxyServiceRequestCorrelationMap().put(requestId,
								specificService.getProxyServiceRequestCorrelationMap().get(specificAuthnRequest.getId()));
						specificService.getProxyServiceRequestCorrelationMap().remove(specificAuthnRequest.getId());
						
						specificService.getSpecificIdpRequestCorrelationMap().put(requestId,
								specificService.getSpecificIdpRequestCorrelationMap().get(specificResponse.getInResponseToId()));
				        specificService.getSpecificIdpRequestCorrelationMap().remove(specificResponse.getInResponseToId());
						
				        // Creazione richiesta AP
						StringBuilder apUrl = new StringBuilder();
						byte[] apMessage = ((SpecificEidasService)specificService).createSamlAuthNRequest(requestId,
								citizenAuthentication.getSpecAuthenticationNode().getCallBackURL(),
								"http://192.168.89.134:8080/EidasNode/ServiceRequesterMetadata",
								newID,
								missingAttributes,
								apMetadataUrl,
								apUrl);
						
						// Preparazione al redirect
						String samlToken = EidasStringUtil.encodeToBase64(apMessage);
						httpServletRequest.setAttribute(EidasParameterKeys.BINDING.toString(), EidasSamlBinding.POST.getName());
		                httpServletRequest.setAttribute(SpecificParameterNames.SAML_TOKEN.toString(), samlToken);
		                httpServletRequest.setAttribute("apUrl", apUrl.toString());
		                return null;
						
					} catch (Exception e) {
						LOGGER.error(e.getMessage());
						authenticationResponse = AuthenticationResponse.builder(specificResponse)
								.failure(true)
								.statusCode(EidasErrors.get(EidasErrorKey.INVALID_ATTRIBUTE_LIST.errorCode()))
								.statusMessage(message)
								.inResponseTo(proxyServiceRequest.getRequest().getId())
								.build();
					}
            	}

            }
        }
        specificService.getProxyServiceRequestCorrelationMap().remove(specificAuthnRequest.getId());
        specificService.getSpecificIdpRequestCorrelationMap().remove(specificResponse.getInResponseToId());
		requestAttributeProviderCorrelationMap.remove(specificResponse.getInResponseToId());
        //build the LightResponse
        return LightResponse.builder(authenticationResponse).build();
    }
    

	@Override
    public void setResponseCallbackHandler(@Nonnull IResponseCallbackHandler responseCallbackHandler) {
        throw new UnsupportedOperationException("Not implemented!");
    }

    private void handleStorkAssertionConsumerUrl(Map<String, Object> parameters, IAUService specificService) {
        // Correct URl redirect cookie implementation
        String callbackURL = specificService.getCallBackURL();
        LOGGER.debug("Setting callbackURL: " + callbackURL);

        NormalParameterValidator.paramName(EIDAS_SERVICE_CALLBACK).paramValue(callbackURL).validate();

        parameters.put(EIDAS_SERVICE_CALLBACK.toString(), callbackURL);
    }

    private String getSamlResponse(@Nonnull HttpServletRequest httpServletRequest) {
        String samlResponse = httpServletRequest.getParameter(EidasParameterKeys.SAML_RESPONSE.toString());

        NormalParameterValidator.paramName(EidasParameterKeys.SAML_RESPONSE)
                .paramValue(samlResponse)
                .eidasError(EidasErrorKey.IDP_SAML_RESPONSE)
                .validate();
        return samlResponse;
    }

    private StoredLightRequest getStoredLightRequest(IAUService specificService,
                                                     String Id)
            throws SpecificException {

        CorrelationMap<StoredLightRequest> proxyServiceRequestCorrelationMap =
                specificService.getProxyServiceRequestCorrelationMap();
        StoredLightRequest proxyServiceRequest = proxyServiceRequestCorrelationMap.get(Id);

        if (null == proxyServiceRequest) {
            LOGGER.error(
                    "ProxyService Request cannot be found for Specific Request ID: \"" + Id
                            + "\"");
            throw new SpecificException(
                    "ProxyService Request cannot be found for Specific Request ID: \"" + Id
                            + "\"");
        }
        //clean up
        //proxyServiceRequestCorrelationMap.remove(specificAuthnRequest.getId());

        return proxyServiceRequest;
    }

    
    // --- MOD ---
    private List<AttributeDefinition<?>> getMissingAttributes(ImmutableAttributeMap requestedA, ImmutableAttributeMap responseA){
    	List<AttributeDefinition<?>> missingAttributes = null;
    	for (final AttributeDefinition<?> attributeDefinition : requestedA.getDefinitions()) {
			if(!(responseA.getDefinitions().contains(attributeDefinition))
					&& !PersonType.REPV_LEGAL_PERSON.equals(attributeDefinition.getPersonType())
                    && !PersonType.REPV_NATURAL_PERSON.equals(attributeDefinition.getPersonType())){
				if(missingAttributes == null)
					missingAttributes = new ArrayList<AttributeDefinition<?>>();
				missingAttributes.add(attributeDefinition);
			}
		}
    	return missingAttributes;
    }
    
    private boolean isAttributeListValid(IAUService specificService,
                                         ImmutableAttributeMap requestedAttributes,
                                         ImmutableAttributeMap responseAttributes) {

        return specificService.compareAttributeLists(requestedAttributes, responseAttributes);
    }
}
