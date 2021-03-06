/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.cloud.deployment.secret.handler.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.wso2.carbon.cloud.deployment.secret.handler.CustomSecretCallbackHandler;

@Component(
        name = "CustomSecretCallbackHandlerServiceComponent",
        immediate = true
)
public class CustomSecretCallbackHandlerServiceComponent {

    private static final Log log = LogFactory.getLog(CustomSecretCallbackHandlerServiceComponent.class);

    /**
     * activate custom Custom Secret Call back Handler.
     *
     * @param componentContext the Component Context
     */
    @Activate
    protected void activate(ComponentContext componentContext) {

        try {
            final CustomSecretCallbackHandler customSecretCallbackHandler = new CustomSecretCallbackHandler();
            componentContext.getBundleContext()
                    .registerService(CustomSecretCallbackHandler.class.getName(), customSecretCallbackHandler, null);
            if (log.isDebugEnabled()) {
                log.debug("Custom Secret Call back Handler is activated.");
            }
        } catch (Throwable e) {
            log.error("Error while activating Custom Secret Call back Handler bundle.", e);
        }
    }

    /**
     * deactivate custom authenticator.
     *
     * @param componentContext the Component Context
     */
    @Deactivate
    protected void deactivate(ComponentContext componentContext) {

        if (log.isDebugEnabled()) {
            log.debug("Custom Secret Call back Handler is deactivated.");
        }
    }
}
