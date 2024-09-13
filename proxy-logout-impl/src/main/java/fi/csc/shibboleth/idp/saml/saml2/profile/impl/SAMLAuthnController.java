/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package fi.csc.shibboleth.idp.saml.saml2.profile.impl;

import java.io.IOException;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Function;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.i18n.SessionLocaleResolver;

import fi.csc.saml.ext.vetuma.LanguageTag;
import fi.csc.saml.ext.vetuma.VetumaExtension;
import fi.csc.saml.ext.vetuma.impl.LanguageTagBuilder;
import fi.csc.saml.ext.vetuma.impl.VetumaExtensionBuilder;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import net.shibboleth.idp.authn.ExternalAuthentication;
import net.shibboleth.idp.authn.ExternalAuthenticationException;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.saml.saml2.profile.impl.SAMLAuthnContext;
import net.shibboleth.profile.context.RelyingPartyContext;
import net.shibboleth.shared.collection.CollectionSupport;
import net.shibboleth.shared.component.AbstractInitializableComponent;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.primitive.LoggerFactory;

import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.messaging.handler.MessageHandler;
import org.opensaml.messaging.handler.MessageHandlerException;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.EventContext;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.common.binding.BindingDescriptor;
import org.opensaml.saml.common.binding.SAMLBindingSupport;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Extensions;
import org.opensaml.saml.saml2.core.impl.ExtensionsBuilder;

/**
 * MVC controller that handles outbound and inbound message I/O for proxied SAML
 * authentication.
 * 
 * <p>
 * Outbound messaging is necessary to ensure webflow hygiene with respect to
 * flow state, and inbound messaging is necessary to ensure a fixed URL for SAML
 * endpoint management.
 * </p>
 * 
 * @since 4.0.0
 */
@Controller
@RequestMapping("%{idp.authn.SAML.externalAuthnPath:/Authn/SAML2}")
public class SAMLAuthnController extends AbstractInitializableComponent {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(SAMLAuthnController.class);

    /** Lookup strategy to locate the nested ProfileRequestContext. */
    @Nonnull
    private Function<ProfileRequestContext, ProfileRequestContext> profileRequestContextLookupStrategy;

    /** Lookup strategy to locate the SAML context. */
    @Nonnull
    private Function<ProfileRequestContext, SAMLAuthnContext> samlContextLookupStrategy;

    /** Map of binding short names to deduce inbound binding constant. */
    @Nonnull
    private Map<String, BindingDescriptor> bindingMap;

    @Value("%{proxylogout.vetumaRegExp:https://testi.apro.tunnistus.fi/idp1|https://tunnistautuminen.suomi.fi/idp1}")
    private String vetumaRegExp;

    @Value("#{%{proxylogout.vetumaLocales:{'fi','sv','en','FI','SV','EN'}}}")
    private List<String> supportedLocales;

    /** Constructor. */
    public SAMLAuthnController() {
        // PRC -> AC -> nested PRC
        final Function<ProfileRequestContext, ProfileRequestContext> prcls = new ChildContextLookup<>(
                ProfileRequestContext.class).compose(new ChildContextLookup<>(AuthenticationContext.class));
        assert prcls != null;
        profileRequestContextLookupStrategy = prcls;

        // PRC -> AC -> SAMLAuthnContext
        final Function<ProfileRequestContext, SAMLAuthnContext> scls = new ChildContextLookup<>(SAMLAuthnContext.class)
                .compose(new ChildContextLookup<>(AuthenticationContext.class));
        assert scls != null;
        samlContextLookupStrategy = scls;

        bindingMap = CollectionSupport.emptyMap();
    }

    /**
     * Set the lookup strategy used to locate the nested
     * {@link ProfileRequestContext}.
     * 
     * @param strategy lookup strategy
     */
    public void setProfileRequestContextLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, ProfileRequestContext> strategy) {
        checkSetterPreconditions();
        profileRequestContextLookupStrategy = Constraint.isNotNull(strategy,
                "ProfileRequestContext lookup strategy cannot be null");
    }

    /**
     * Set the lookup strategy used to locate the {@link SAMLAuthnContext}.
     * 
     * @param strategy lookup strategy
     */
    public void setSAMLAuthnContextLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, SAMLAuthnContext> strategy) {
        checkSetterPreconditions();
        samlContextLookupStrategy = Constraint.isNotNull(strategy, "SAMLAuthnContext lookup strategy cannot be null");
    }

    /**
     * Set inbound bindings to use to deduce ProtocolBinding attribute.
     * 
     * @param bindings the bindings to set
     */
    public void setInboundBindings(@Nullable final Collection<BindingDescriptor> bindings) {
        checkSetterPreconditions();
        if (bindings != null) {
            bindingMap = new HashMap<>(bindings.size());
            bindings.forEach(b -> bindingMap.put(b.getShortName(), b));
        } else {
            bindingMap = CollectionSupport.emptyMap();
        }
    }

// Checkstyle: CyclomaticComplexity OFF
    /**
     * Outbound initiation of the process, triggered with a fixed addition to the
     * path.
     * 
     * @param httpRequest  servlet request
     * @param httpResponse servlet response
     * 
     * @throws ExternalAuthenticationException if an error occurs
     * @throws IOException                     if an I/O error occurs
     */
    @GetMapping("/POST/SSO/startext")
    public void startSAML(@Nonnull final HttpServletRequest httpRequest,
            @Nonnull final HttpServletResponse httpResponse) throws ExternalAuthenticationException, IOException {

        final String key = ExternalAuthentication.startExternalAuthentication(httpRequest);
        final ProfileRequestContext prc = ExternalAuthentication.getProfileRequestContext(key, httpRequest);

        final SAMLAuthnContext samlContext = samlContextLookupStrategy.apply(prc);
        if (samlContext == null) {
            log.error("SAMLAuthnContext not found");
            httpRequest.setAttribute(ExternalAuthentication.AUTHENTICATION_ERROR_KEY, EventIds.INVALID_PROFILE_CTX);
            ExternalAuthentication.finishExternalAuthentication(key, httpRequest, httpResponse);
            return;
        }

        final ProfileRequestContext nestedPRC = profileRequestContextLookupStrategy.apply(prc);
        if (nestedPRC == null) {
            log.error("Nested ProfileRequestContext not found");
            httpRequest.setAttribute(ExternalAuthentication.AUTHENTICATION_ERROR_KEY, EventIds.INVALID_PROFILE_CTX);
            ExternalAuthentication.finishExternalAuthentication(key, httpRequest, httpResponse);
            return;
        }
        RelyingPartyContext rpCtx = nestedPRC.getSubcontext(RelyingPartyContext.class);
        if (rpCtx == null) {
            log.error("RelyingPartyContext of nested ProfileRequestContext not found");
            httpRequest.setAttribute(ExternalAuthentication.AUTHENTICATION_ERROR_KEY, EventIds.INVALID_PROFILE_CTX);
            ExternalAuthentication.finishExternalAuthentication(key, httpRequest, httpResponse);
            return;
        }

        // Fill in the AuthnRequest's ACS URL and set RelayState to the EA key.
        final MessageContext nestedOmc = nestedPRC.getOutboundMessageContext();
        if (nestedOmc != null && nestedOmc.getMessage() instanceof AuthnRequest authnRequest) {
            SAMLBindingSupport.setRelayState(nestedOmc, key);
            final StringBuffer url = httpRequest.getRequestURL();
            authnRequest.setAssertionConsumerServiceURL(url.substring(0, url.lastIndexOf("/startext")));
            final BindingDescriptor bd = bindingMap.get("POST");
            if (bd != null) {
                authnRequest.setProtocolBinding(bd.ensureId());
            }
            if (rpCtx.getRelyingPartyId().matches(vetumaRegExp)) {

                Locale locale = new SessionLocaleResolver().resolveLocale(httpRequest);
                if (locale != null && supportedLocales.contains(locale.getLanguage())) {
                    LanguageTag lg = new LanguageTagBuilder().buildObject();
                    lg.setValue(locale.getLanguage());
                    VetumaExtension tag = new VetumaExtensionBuilder().buildObject();
                    tag.getLGs().add(lg);
                    final Extensions extensions = new ExtensionsBuilder().buildObject();
                    extensions.getUnknownXMLObjects().add(tag);
                    authnRequest.setExtensions(extensions);
                }
            }

        } else {
            httpRequest.setAttribute(ExternalAuthentication.AUTHENTICATION_ERROR_KEY, EventIds.INVALID_MESSAGE);
            ExternalAuthentication.finishExternalAuthentication(key, httpRequest, httpResponse);
            return;
        }

        try {
            final MessageHandler handler = samlContext.getOutboundMessageHandler();
            if (handler != null) {
                handler.invoke(nestedOmc);
            }
            samlContext.getEncodeMessageAction().execute(nestedPRC);
            final EventContext eventCtx = nestedPRC.getSubcontext(EventContext.class);
            final Object event = eventCtx != null ? eventCtx.getEvent() : null;
            if (event != null && !EventIds.PROCEED_EVENT_ID.equals(event)) {
                log.error("Message encoding action signaled non-proceed event {}", event);
                httpRequest.setAttribute(ExternalAuthentication.AUTHENTICATION_ERROR_KEY, event.toString());
                ExternalAuthentication.finishExternalAuthentication(key, httpRequest, httpResponse);
                return;
            }
        } catch (final MessageHandlerException e) {
            log.error("Caught message handling exception", e);
            httpRequest.setAttribute(ExternalAuthentication.AUTHENTICATION_ERROR_KEY, EventIds.MESSAGE_PROC_ERROR);
            ExternalAuthentication.finishExternalAuthentication(key, httpRequest, httpResponse);
        }
    }

}
