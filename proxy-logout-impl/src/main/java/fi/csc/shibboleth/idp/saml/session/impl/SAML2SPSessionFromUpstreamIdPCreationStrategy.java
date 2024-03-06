
package fi.csc.shibboleth.idp.saml.session.impl;

import java.time.Duration;
import java.time.Instant;
import java.util.Set;
import java.util.function.Function;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.saml2.core.NameID;
import org.slf4j.Logger;
import net.shibboleth.shared.primitive.LoggerFactory;
import net.shibboleth.idp.authn.context.SubjectContext;
import net.shibboleth.idp.saml.authn.principal.NameIDPrincipal;
import net.shibboleth.idp.saml.session.SAML2SPSession;
import net.shibboleth.idp.session.SPSession;
import net.shibboleth.shared.logic.Constraint;

/**
 * A function to create a {@link SAML2SPSession} based on profile execution
 * state.
 * 
 * <p>
 * This strategy uses a {@link SubjectContext} to obtain Subjects
 * {@link NameIDPrincipal} from upstream to populate {@link SPSession}'s for
 * upstream IdP. The session has a creation time based on the time of execution,
 * and the expiration is based on a configurable lifetime, bounded by the per-SP
 * lifetime setting for the profile.
 * </p>
 * 
 * <p>
 * The SAML 2 specific data is extracted from the subjects first
 * {@link NameIDPrincipal}.
 * </p>
 */

//TODO: Should check that IdP has also SP role and logout - end point, otherwise logout and propagation will not work
public class SAML2SPSessionFromUpstreamIdPCreationStrategy implements Function<ProfileRequestContext, SPSession> {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(SAML2SPSessionFromUpstreamIdPCreationStrategy.class);

    /** Lifetime of sessions to create. */
    @Nonnull
    private final Duration sessionLifetime;

    /**
     * Constructor.
     * 
     * @param lifetime determines upper bound for expiration of
     *                 {@link SAML2SPSession} to be created
     */
    public SAML2SPSessionFromUpstreamIdPCreationStrategy(@Nonnull final Duration lifetime) {
        sessionLifetime = Constraint.isNotNull(lifetime, "Lifetime cannot be null");
    }

    /** {@inheritDoc} */
    @Nullable
    public SPSession apply(@Nullable final ProfileRequestContext input) {

        assert input != null;
        SubjectContext subjectCtx = input.getSubcontext(SubjectContext.class);
        if (subjectCtx == null) {
            log.debug("No SubjectContext, no SAML2SPSession created");
            return null;
        }
        NameID nameID = null;
        for (javax.security.auth.Subject subject : subjectCtx.getSubjects()) {
            Set<NameIDPrincipal> nameIds = subject.getPrincipals(NameIDPrincipal.class);
            // We assume there is at most one name NameIDPrincipal
            if (nameIds != null && !nameIds.isEmpty()) {
                nameID = nameIds.iterator().next().getNameID();
            }
            break;
        }
        if (nameID == null) {
            log.debug("No NameIDPrincipal in SubjectContext, no SAML2SPSession created");
            return null;
        }
        // TODO: We read session id from sp provided id field. Very suspicious hack. Fix
        // it.
        String sessionIndex = nameID.getSPProvidedID();
        if (sessionIndex == null) {
            log.debug("No session index avalaible, no SAML2SPSession created");
            return null;
        }
        // We clear it before creating a SP Session.
        nameID.setSPProvidedID(null);
        return new SAML2SPSession(nameID.getNameQualifier(), Instant.now(), Instant.now().plus(sessionLifetime), nameID,
                sessionIndex, null, true);
    }
}