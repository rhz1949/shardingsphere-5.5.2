/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.shardingsphere.infra.algorithm.messagedigest.sm3;

import lombok.SneakyThrows;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.shardingsphere.infra.algorithm.messagedigest.core.MessageDigestAlgorithm;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Security;
import java.util.Base64;
import java.security.GeneralSecurityException;


import java.util.Properties;

/**
 * SM3 message digest algorithm.
 */
public final class SM3MessageDigestAlgorithm implements MessageDigestAlgorithm {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    
    private static final String SALT_KEY = "salt";
    
    private String salt;
    
    @Override
    public void init(final Properties props) {
        salt = props.getProperty(SALT_KEY, "");
    }
    
    @SneakyThrows(GeneralSecurityException.class)
    @Override
    public String digest(final Object plainValue) {

        if (null == plainValue) {
            return null;
        }

        return getDigest(plainValue);
    
    }

    private String getDigest(final Object plainValue) throws GeneralSecurityException {

        MessageDigest md = MessageDigest.getInstance("SM3", "BC");


        return null == plainValue ? null : Base64.getEncoder().encodeToString(
            md.digest((plainValue + salt).toString().getBytes(StandardCharsets.UTF_8)));
    }
    
    @Override
    public String getType() {
        return "SM3";
    }
}
