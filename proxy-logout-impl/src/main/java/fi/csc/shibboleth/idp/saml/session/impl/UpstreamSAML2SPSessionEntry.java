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
                if (SAML2SPSessionFromUpstreamIdPCreationStrategy.ACS.equals(spSession.getACSLocation())) {
                    log.trace("Located upstream session {}", entry.getKey());
                    return entry.getKey();
                }
            }
        }
        return null;
    }
}