package fi.csc.saml.ext.vetuma.impl;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.core.xml.schema.impl.XSStringImpl;

import fi.csc.saml.ext.vetuma.LanguageTag;

public class LanguageTagImpl extends XSStringImpl implements LanguageTag {

    protected LanguageTagImpl(@Nullable final String namespaceURI, @Nonnull final String elementLocalName,
            @Nullable final String namespacePrefix) {
        super(namespaceURI, elementLocalName, namespacePrefix);
    }

}