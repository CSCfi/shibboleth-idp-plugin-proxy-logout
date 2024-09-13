package fi.csc.saml.ext.vetuma;

import javax.annotation.Nonnull;
import javax.xml.namespace.QName;

import org.opensaml.core.xml.schema.XSString;
import org.opensaml.saml.common.SAMLObject;

import net.shibboleth.shared.annotation.constraint.NotEmpty;

public interface LanguageTag extends SAMLObject, XSString {

    /** Element local name. */
    @Nonnull
    @NotEmpty
    static final String DEFAULT_ELEMENT_LOCAL_NAME = "LG";

    /** Default element name. */
    @Nonnull
    static final QName DEFAULT_ELEMENT_NAME = new QName(VetumaExtension.NS, DEFAULT_ELEMENT_LOCAL_NAME,
            VetumaExtension.PREFIX);

}