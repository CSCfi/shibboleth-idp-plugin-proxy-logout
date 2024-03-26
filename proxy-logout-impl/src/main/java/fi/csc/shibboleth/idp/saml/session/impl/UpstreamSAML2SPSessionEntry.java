
package fi.csc.shibboleth.idp.saml.session.impl;

import java.util.Map.Entry;
import java.util.function.Function;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.slf4j.Logger;
import net.shibboleth.shared.primitive.LoggerFactory;
import net.shibboleth.idp.saml.session.SAML2SPSession;
import net.shibboleth.idp.session.SPSession;
import net.shibboleth.idp.session.context.LogoutContext;

public class UpstreamSAML2SPSessionEntry implements Function<LogoutContext, String> {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(UpstreamSAML2SPSessionEntry.class);

    /** {@inheritDoc} */
    @Nullable
    public String apply(@Nullable final LogoutContext input) {

        assert input != null;
        for (Entry<String, SPSession> entry : input.getKeyedSessionMap().entrySet()) {
            log.trace("Searching for upstream session {}", entry.getKey());
            if (entry.getValue() instanceof SAML2SPSession) {
                SAML2SPSession spSession = (SAML2SPSession) entry.getValue();
                if (spSession.getACSLocation() == null || spSession.getACSLocation().isBlank()) {
                    log.trace("Located upstream session {}", entry.getKey());
                    return entry.getKey();
                }
            }
        }
        return null;
    }
}