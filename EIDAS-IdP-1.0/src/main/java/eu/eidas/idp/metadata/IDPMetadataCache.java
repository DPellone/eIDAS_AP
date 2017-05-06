package eu.eidas.idp.metadata;
/*
 * Copyright (c) 2016 by European Commission
 *
 * Licensed under the EUPL, Version 1.1 or - as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence");
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 * http://www.osor.eu/eupl/european-union-public-licence-eupl-v.1.1
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 *
 * This product combines work with different licenses. See the "NOTICE" text
 * file for details on the various modules and licenses.
 * The "NOTICE" text file is part of the distribution. Any derivative works
 * that you distribute must include a readable copy of the "NOTICE" text file.
 *
 */

import com.google.common.cache.CacheBuilder;
import eu.eidas.auth.commons.EidasStringUtil;
import eu.eidas.auth.commons.xml.opensaml.OpenSamlHelper;
import eu.eidas.auth.engine.metadata.EntityDescriptorContainer;
import eu.eidas.auth.engine.metadata.EntityDescriptorType;
import eu.eidas.auth.engine.metadata.IMetadataCachingService;
import eu.eidas.auth.engine.metadata.MetadataGenerator;
import eu.eidas.encryption.exception.MarshallException;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.signature.SignableXMLObject;

import javax.annotation.Nonnull;
import java.util.Map;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;

public class IDPMetadataCache implements IMetadataCachingService {

    private static final String SIGNATURE_HOLDER_ID_PREFIX="signatureholder";

    private final ConcurrentMap<String, SerializedEntityDescriptor> map = CacheBuilder.newBuilder()
            .expireAfterAccess(1L, TimeUnit.DAYS)
            .maximumSize(10000L).<String, SerializedEntityDescriptor>build().asMap();

    protected Map<String, SerializedEntityDescriptor> getMap() {
        return map;
    }

    private class SerializedEntityDescriptor {
        /**
         * the entitydescriptor serialized as xml
         */
        private String serializedEntityDescriptor;

        /**
         * the type/origin (either statically loaded or retrieved from the network)
         */
        private EntityDescriptorType type;

        public SerializedEntityDescriptor(String descriptor, EntityDescriptorType type) {
            setSerializedEntityDescriptor(descriptor);
            setType(type);
        }

        public String getSerializedEntityDescriptor() {
            return serializedEntityDescriptor;
        }

        public void setSerializedEntityDescriptor(String serializedEntityDescriptor) {
            this.serializedEntityDescriptor = serializedEntityDescriptor;
        }

        public EntityDescriptorType getType() {
            return type;
        }

        public void setType(EntityDescriptorType type) {
            this.type = type;
        }
    }


    @Override
    public final EntityDescriptor getDescriptor(String url) {
        if(getMap()!=null){
            SerializedEntityDescriptor content=getMap().get(url);
            if(content!=null && !content.getSerializedEntityDescriptor().isEmpty()) {
                return deserializeEntityDescriptor(content.getSerializedEntityDescriptor());
            }
        }
        return null;
    }

    @Override
    public final void putDescriptor(String url, EntityDescriptor ed, EntityDescriptorType type) {
        if(getMap()!=null){
            if(ed==null){
                getMap().remove(url);
            }else {
                String content = serializeEntityDescriptor(ed);
                if (content != null && !content.isEmpty()) {
                    getMap().put(url, new SerializedEntityDescriptor(content, type));
                }
            }
        }
    }
    @Override
    public final EntityDescriptorType getDescriptorType(String url) {
        if (getMap() != null) {
            SerializedEntityDescriptor content = getMap().get(url);
            if (content != null) {
                return content.getType();
            }
        }
        return null;
    }

    private String serializeEntityDescriptor(XMLObject ed){
        try {
            return EidasStringUtil.toString(OpenSamlHelper.marshall(ed));
        } catch (MarshallException e) {
            throw new IllegalStateException(e);
        }
    }

    private EntityDescriptor deserializeEntityDescriptor(String content){
        EntityDescriptorContainer container = MetadataGenerator.deserializeEntityDescriptor(content);
        return container.getEntityDescriptors().isEmpty()?null:container.getEntityDescriptors().get(0);
    }

    @Override
    public SignableXMLObject getDescriptorSignatureHolder(@Nonnull String url){
        SerializedEntityDescriptor sed = getMap().get(SIGNATURE_HOLDER_ID_PREFIX+url);
        if(sed!=null){
            EntityDescriptorContainer edc;
            edc = MetadataGenerator.deserializeEntityDescriptor(sed.getSerializedEntityDescriptor());
            if(edc.getEntitiesDescriptor()!=null){
                return edc.getEntitiesDescriptor();
            }
        }
        return getDescriptor(url);
    }
    @Override
    public void putDescriptorSignatureHolder(String url, SignableXMLObject container){
        getMap().put(SIGNATURE_HOLDER_ID_PREFIX+url, new SerializedEntityDescriptor(serializeEntityDescriptor(container), EntityDescriptorType.NONE));
    }

    @Override
    public void putDescriptorSignatureHolder(String url, EntityDescriptorContainer container){
        if(container.getSerializedEntitesDescriptor()!=null){
            getMap().put(SIGNATURE_HOLDER_ID_PREFIX+url, new SerializedEntityDescriptor(EidasStringUtil.toString(container.getSerializedEntitesDescriptor()), EntityDescriptorType.SERIALIZED_SIGNATURE_HOLDER));
        }else{
            putDescriptorSignatureHolder(url, container.getEntitiesDescriptor());
        }
    }

}