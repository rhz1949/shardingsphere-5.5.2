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

package org.apache.shardingsphere.infra.algorithm.cryptographic.sm4;

import lombok.SneakyThrows;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.shardingsphere.infra.algorithm.core.exception.AlgorithmInitializationException;
import org.apache.shardingsphere.infra.algorithm.cryptographic.core.CryptographicAlgorithm;
import org.apache.shardingsphere.infra.exception.core.ShardingSpherePreconditions;


import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;
import java.util.Properties;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * SM4 cryptographic algorithm.
 */
public final class SM4CryptographicAlgorithm implements CryptographicAlgorithm {
    
    private static final String SM4_KEY = "sm4-key-value";
    
    private static final String DIGEST_ALGORITHM_NAME = "digest-algorithm-name";

    private static final String SM4_IV = "sm4-iv-value";

    private static final String SM4_MODE = "sm4-mode";

    private static final byte[] SM4_IV_DEFAULT = new byte[] {0x40, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46};
    
    private byte[] secretKey;

    private byte[] iv;

    private String sm4_mode;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    
    @Override
    public void init(final Properties props) {
        secretKey = getSecretKey(props);
        iv = getIV(props);
        sm4_mode = getSM4Mode(props);
    }

    private byte[] getIV(final Properties props) {
        
        String sm4IV = props.getProperty(SM4_IV, "");
        if (sm4IV.isEmpty()) {
            return SM4_IV_DEFAULT;
        }

        byte[] iv = Arrays.copyOf(DigestUtils.md5(sm4IV.getBytes(StandardCharsets.UTF_8)), 16);

        return iv;
    }

    private String getSM4Mode(final Properties props) {
        
        String sm4Mode = props.getProperty(SM4_MODE, "ECB").toUpperCase();

        if (!sm4Mode.equals("ECB") && !sm4Mode.equals("CBC")) {
            return "ECB";
        }

        return sm4Mode;
    }


    
    private byte[] getSecretKey(final Properties props) {
        String sm4Key = props.getProperty(SM4_KEY);
        ShardingSpherePreconditions.checkNotEmpty(sm4Key, () -> new AlgorithmInitializationException(this, "%s can not be null or empty", SM4_KEY));

        // String digestAlgorithm = props.getProperty(DIGEST_ALGORITHM_NAME);
        // ShardingSpherePreconditions.checkNotEmpty(digestAlgorithm, () -> new AlgorithmInitializationException(this, "%s can not be null or empty", DIGEST_ALGORITHM_NAME));
        String digestAlgorithm = props.getProperty(DIGEST_ALGORITHM_NAME, "MD5");

        return Arrays.copyOf(DigestUtils.getDigest(digestAlgorithm.toUpperCase()).digest(sm4Key.getBytes(StandardCharsets.UTF_8)), 16);
    }
    
    @SneakyThrows(GeneralSecurityException.class)
    @Override
    public String encrypt(final Object plainValue) {
        if (null == plainValue) {
            return null;
        }
        
        byte[] result = getCipher(Cipher.ENCRYPT_MODE).doFinal(String.valueOf(plainValue).getBytes(StandardCharsets.UTF_8));

        return Base64.getEncoder().encodeToString(result);
    }
    
    @SneakyThrows(GeneralSecurityException.class)
    @Override
    public Object decrypt(final Object cipherValue) {
        if (null == cipherValue) {
            return null;
        }

        byte[] result = getCipher(Cipher.DECRYPT_MODE).doFinal(Base64.getDecoder().decode(cipherValue.toString().trim()));
        return new String(result, StandardCharsets.UTF_8);

    }
    
    private Cipher getCipher(final int decryptMode) throws GeneralSecurityException {

        if (sm4_mode.equals("CBC")) {
            Cipher result = Cipher.getInstance("SM4/CBC/PKCS5Padding", "BC");
            result.init(decryptMode, new SecretKeySpec(secretKey, getType()), new IvParameterSpec(iv));
            return result;
        }


        Cipher result = Cipher.getInstance("SM4/ECB/PKCS5Padding", "BC");
        result.init(decryptMode, new SecretKeySpec(secretKey, getType()));
        return result;
        
    }
    
    @Override
    public String getType() {
        return "SM4";
    }

    // public String getSm4_mode() {
    //     return sm4_mode;
    // }
}