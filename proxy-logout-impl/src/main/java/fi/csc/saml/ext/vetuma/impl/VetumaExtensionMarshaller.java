package fi.csc.saml.ext.vetuma.impl;

import javax.annotation.Nonnull;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.common.AbstractSAMLObjectMarshaller;
import org.w3c.dom.Element;

import fi.csc.saml.ext.vetuma.LanguageTag;
import fi.csc.saml.ext.vetuma.VetumaExtension;

public class VetumaExtensionMarshaller extends AbstractSAMLObjectMarshaller {

    @Override
    protected void marshallElementContent(@Nonnull final XMLObject samlElement, @Nonnull final Element domElement)
            throws MarshallingException {
        final VetumaExtension langTag = (VetumaExtension) samlElement;

        if (langTag.getLGs() != null && !langTag.getLGs().isEmpty()) {
            Element element = domElement.getOwnerDocument().createElementNS(VetumaExtension.NS,
                    LanguageTag.DEFAULT_ELEMENT_LOCAL_NAME);
            element.appendChild(domElement.getOwnerDocument().createTextNode(langTag.getLGs().get(0).getValue()));
            domElement.appendChild(element);
        }
    }

}
