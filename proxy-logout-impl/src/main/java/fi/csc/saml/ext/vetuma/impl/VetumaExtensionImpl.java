package fi.csc.saml.ext.vetuma.impl;

import java.util.List;

import javax.annotation.Nonnull;
import javax.xml.namespace.QName;

import org.opensaml.core.xml.AbstractXMLObject;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.util.AttributeMap;
import org.opensaml.core.xml.util.IndexedXMLObjectChildrenList;

import fi.csc.saml.ext.vetuma.LanguageTag;
import fi.csc.saml.ext.vetuma.VetumaExtension;
import net.shibboleth.shared.annotation.constraint.Live;

public class VetumaExtensionImpl extends AbstractXMLObject implements VetumaExtension {

    /** Children of the VetumaExtension. */
    @Nonnull
    private final IndexedXMLObjectChildrenList<XMLObject> children;

    /** "anyAttribute" attributes. */
    @Nonnull
    private final AttributeMap unknownAttributes;

    protected VetumaExtensionImpl(String namespaceURI, String elementLocalName, String namespacePrefix) {
        super(namespaceURI, elementLocalName, namespacePrefix);
        children = new IndexedXMLObjectChildrenList<>(this);
        unknownAttributes = new AttributeMap(this);
    }

    @Override
    public List<XMLObject> getOrderedChildren() {
        // TODO Auto-generated method stub
        return null;
    }

    @SuppressWarnings("unchecked")
    @Override
    public List<LanguageTag> getLGs() {
        return (List<LanguageTag>) children.subList(LanguageTag.DEFAULT_ELEMENT_NAME);
    }

    /** {@inheritDoc} */
    @Nonnull
    @Live
    public List<XMLObject> getXMLObjects() {
        return children;
    }

    /** {@inheritDoc} */
    @SuppressWarnings("unchecked")
    @Nonnull
    @Live
    public List<XMLObject> getXMLObjects(@Nonnull final QName typeOrName) {
        return (List<XMLObject>) children.subList(typeOrName);
    }

    /** {@inheritDoc} */
    @Nonnull
    public AttributeMap getUnknownAttributes() {
        return unknownAttributes;
    }

}
