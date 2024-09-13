package fi.csc.saml.ext.vetuma;

import java.util.List;

import javax.annotation.Nonnull;
import javax.xml.namespace.QName;

import org.opensaml.core.xml.AttributeExtensibleXMLObject;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.common.SAMLObject;

import net.shibboleth.shared.annotation.constraint.Live;
import net.shibboleth.shared.annotation.constraint.NotEmpty;

public interface VetumaExtension extends SAMLObject, AttributeExtensibleXMLObject {

    /** Name of the element inside the Extensions. */
    @Nonnull
    @NotEmpty
    static final String DEFAULT_ELEMENT_LOCAL_NAME = "vetuma";

    @Nonnull
    @NotEmpty
    static final String NS = "urn:vetuma:SAML:2.0:extensions";

    @Nonnull
    @NotEmpty
    static final String PREFIX = "vet";

    /** Default element name. */
    @Nonnull
    static final QName DEFAULT_ELEMENT_NAME = new QName(NS, DEFAULT_ELEMENT_LOCAL_NAME, VetumaExtension.PREFIX);

    /** Local name of the XSI type. */
    @Nonnull
    @NotEmpty
    static final String TYPE_LOCAL_NAME = "vetuma";

    /** QName of the XSI type. */
    @Nonnull
    static final QName TYPE_NAME = new QName(NS, TYPE_LOCAL_NAME, VetumaExtension.PREFIX);

    /** Local name of the XSI type. */
    @Nonnull
    @Live
    List<LanguageTag> getLGs();

    /**
     * Get the list of all children of this element.
     * 
     * @return the list of all XMLObject children
     */
    @Nonnull
    @Live
    List<XMLObject> getXMLObjects();

    /**
     * Get the list of all children of this element which have the specified name or
     * type.
     * 
     * @param typeOrName the element name or type of the desired list of elements
     * 
     * @return the list of all XMLObject children
     */
    @Nonnull
    @Live
    List<XMLObject> getXMLObjects(@Nonnull final QName typeOrName);

}
