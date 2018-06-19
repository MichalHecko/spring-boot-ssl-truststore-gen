/*
 *
 *  * Copyright (C) 2015 Orange
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  * http://www.apache.org/licenses/LICENSE-2.0
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *  *
 *
 */

package com.mhecko.boot.ssl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationStartedEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.core.Ordered;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.core.io.support.ResourcePatternUtils;

public class SslTrustStoreGeneratorListener implements ApplicationListener<ApplicationStartedEvent>, Ordered {
    private static Logger LOGGER = LoggerFactory.getLogger(SslTrustStoreGeneratorListener.class);

    public static final String SSL_TRUST_STORE_SYSTEM_PROPERTY = "javax.net.ssl.trustStore";
    public static final String SSL_TRUST_STORE_PASSWORD_SYSTEM_PROPERTY = "javax.net.ssl.trustStorePassword";

    private ResourceLoader resourceLoader = new DefaultResourceLoader();

    private int order = HIGHEST_PRECEDENCE;


    public void onApplicationEvent(ApplicationStartedEvent event) {
        try {
            DefaultTrustStoreAppender trustStoreAppender = new DefaultTrustStoreAppender();

            Resource[] resources = ResourcePatternUtils.getResourcePatternResolver(resourceLoader).getResources("classpath*:cert/*");
            if (resources != null) {
                for (Resource resource : resources) {
                    trustStoreAppender.append(CertificateFactory.newInstance(resource));
                }
            }

            TrustStoreInfo trustStoreInfo = trustStoreAppender.build();

            System.setProperty(SSL_TRUST_STORE_SYSTEM_PROPERTY, trustStoreInfo.getTrustStorefFile().getAbsolutePath());
            System.setProperty(SSL_TRUST_STORE_PASSWORD_SYSTEM_PROPERTY, trustStoreInfo.getPassword());

            LOGGER.info("Setting {} system property to {}", SSL_TRUST_STORE_SYSTEM_PROPERTY, trustStoreInfo.getTrustStorefFile().getAbsolutePath());
            LOGGER.info("Setting {} system property to {}", SSL_TRUST_STORE_PASSWORD_SYSTEM_PROPERTY, trustStoreInfo.getPassword());
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    public int getOrder() {
        return order;
    }
}


