package fi.csc.saml.ext.vetuma.impl;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.saml.common.AbstractSAMLObjectBuilder;

import fi.csc.saml.ext.vetuma.VetumaExtension;

public class VetumaExtensionBuilder extends AbstractSAMLObjectBuilder<VetumaExtension> {

    /** {@inheritDoc} */
    @Override
    @Nonnull
    public VetumaExtension buildObject() {
        return buildObject(VetumaExtension.NS, VetumaExtension.DEFAULT_ELEMENT_LOCAL_NAME, VetumaExtension.PREFIX);
    }

    /** {@inheritDoc} */
    @Override
    @Nonnull
    public VetumaExtension buildObject(@Nullable final String namespaceURI, @Nonnull final String localName,
            @Nullable final String namespacePrefix) {
        return new VetumaExtensionImpl(namespaceURI, localName, namespacePrefix);
    }

}
