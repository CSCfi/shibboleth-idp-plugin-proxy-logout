package fi.csc.saml.ext.vetuma.impl;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.saml.common.AbstractSAMLObjectBuilder;

import fi.csc.saml.ext.vetuma.LanguageTag;
import fi.csc.saml.ext.vetuma.VetumaExtension;

public class LanguageTagBuilder extends AbstractSAMLObjectBuilder<LanguageTag> {

    /** {@inheritDoc} */
    @Nonnull
    public LanguageTag buildObject() {
        return buildObject(VetumaExtension.NS, LanguageTag.DEFAULT_ELEMENT_LOCAL_NAME, VetumaExtension.PREFIX);
    }

    /** {@inheritDoc} */
    @Nonnull
    public LanguageTag buildObject(@Nullable final String namespaceURI, @Nonnull final String localName,
            @Nullable final String namespacePrefix) {
        return new LanguageTagImpl(namespaceURI, localName, namespacePrefix);
    }

}