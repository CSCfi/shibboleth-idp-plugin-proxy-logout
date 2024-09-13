package fi.csc.saml.ext.vetuma.impl;

import javax.annotation.Nonnull;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.common.AbstractSAMLObjectUnmarshaller;

import fi.csc.saml.ext.vetuma.LanguageTag;
import fi.csc.saml.ext.vetuma.VetumaExtension;

public class VetumaExtensionUnmarshaller extends AbstractSAMLObjectUnmarshaller {

    /** {@inheritDoc} */
    @Override
    protected void processChildElement(@Nonnull final XMLObject parentObject, @Nonnull final XMLObject childObject)
            throws UnmarshallingException {
        final VetumaExtension langTag = (VetumaExtension) parentObject;
        langTag.getXMLObjects().add(childObject);
        if (childObject instanceof LanguageTag) {
            langTag.getLGs().add((LanguageTag) childObject);
        }
    }

}