/*
 * Copyright (c) 2024 CSC- IT Center for Science, www.csc.fi
 * 
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

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.shibboleth.idp.profile.AbstractProfileAction;

/**
 * Stores context path parameter value to session. If base url has been defined
 * checks also that context path is compatible with base url adding a forward
 * slash if needed.
 */
public class StoreContextPath extends AbstractProfileAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(StoreContextPath.class);

    /** Name of the context path parameter. */
    @Nonnull
    private String contextPathParameter = "context_path";

    /** base url. */
    @Nullable
    private String baseUrl;

    /**
     * Set name of the context path parameter.
     * 
     * @param parameter Name of the context path parameter
     */
    public void setContextPathParameter(@Nonnull String parameter) {
        checkSetterPreconditions();
        assert parameter != null;
        contextPathParameter = parameter;
    }

    /**
     * Set baseUrl.
     * 
     * @param parameter baseUrl
     */
    public void setBaseUrl(@Nonnull String url) {
        checkSetterPreconditions();
        baseUrl = url;
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        String contextPath = (String) getHttpServletRequest().getParameter(contextPathParameter);
        if (contextPath != null && !contextPath.isBlank()) {
            if (baseUrl != null && !baseUrl.endsWith("/") && !contextPath.startsWith("/")) {
                contextPath = "/" + contextPath;
            }
            getHttpServletRequest().getSession()
                    .setAttribute("fi.csc.shibboleth.idp.saml.saml2.profile.impl.StoreContextPath", contextPath);
            log.debug("{} Setting post logout redirect uri context path as '{}'", contextPath);
        } else {
            getHttpServletRequest().getSession()
                    .removeAttribute("fi.csc.shibboleth.idp.saml.saml2.profile.impl.StoreContextPath");
            log.debug("{} Clearing post logout redirect uri context path", contextPath);
        }
    }

}
