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

import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.UUID;


public class DefaultTrustStoreAppender {
    private static Logger LOG = LoggerFactory.getLogger(DefaultTrustStoreAppender.class);

    public static final String TRUSTSTORE_FILENAME = "truststore";

    private final X509TrustManager trustManager;
    private final KeyStore trustStore;


    public DefaultTrustStoreAppender() throws Exception {
        this.trustManager = getDefaultTrustManager();
        this.trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        // vynuluj keystore
        this.trustStore.load(null);

        for (X509Certificate cert : this.trustManager.getAcceptedIssuers()) {
            this.trustStore.setCertificateEntry(UUID.randomUUID().toString(), cert);
            // LOG.debug("Adding existing certificate to truststore {}", cert);
        }
    }

    /**
     * Create new java truststore from default truststore. Add given CA certificate to it.
     *
     * @param certificates
     * @return TrustStoreInfo
     * @see <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/JSSERefGuide.html">JSSE Reference Guide</a>
     */
    public void append(Certificate... certificates) throws KeyStoreException {
        for (Certificate certificate : certificates) {
            if (certificate != null) {
                this.trustStore.setCertificateEntry(UUID.randomUUID().toString(), certificate);
                LOG.debug("Adding new certificate to truststore: {}", certificate);
            }
        }
    }

    public TrustStoreInfo build() throws Exception {
        String password = UUID.randomUUID().toString();
        File trustStoreOutputFile = File.createTempFile(TRUSTSTORE_FILENAME, null);
        trustStoreOutputFile.deleteOnExit();
        trustStore.store(new FileOutputStream(trustStoreOutputFile), password.toCharArray());

        return new TrustStoreInfo(trustStoreOutputFile, password);
    }

    private X509TrustManager getDefaultTrustManager() throws NoSuchAlgorithmException, KeyStoreException {
        TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        factory.init((KeyStore) null);
        return (X509TrustManager) factory.getTrustManagers()[0];
    }
}
