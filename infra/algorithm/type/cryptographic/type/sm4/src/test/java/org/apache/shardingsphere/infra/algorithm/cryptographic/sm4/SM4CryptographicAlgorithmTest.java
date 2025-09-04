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

import org.apache.shardingsphere.infra.algorithm.core.exception.AlgorithmInitializationException;
import org.apache.shardingsphere.infra.algorithm.cryptographic.core.CryptographicAlgorithm;
import org.apache.shardingsphere.infra.spi.type.typed.TypedSPILoader;
import org.apache.shardingsphere.test.util.PropertiesBuilder;
import org.apache.shardingsphere.test.util.PropertiesBuilder.Property;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SM4CryptographicAlgorithmTest {
    
    private CryptographicAlgorithm cryptographicAlgorithm;
    
    private CryptographicAlgorithm cryptographicAlgorithmCBC;
    
    @BeforeEach
    void setUp() {
        cryptographicAlgorithm = TypedSPILoader.getService(CryptographicAlgorithm.class, "SM4",
                PropertiesBuilder.build(new Property("sm4-key-value", "test"), new Property("digest-algorithm-name", "SHA-1")));

        cryptographicAlgorithmCBC = TypedSPILoader.getService(CryptographicAlgorithm.class, "SM4",
                PropertiesBuilder.build(new Property("sm4-key-value", "test"), new Property("digest-algorithm-name", "SHA-1"), new Property("sm4-mode", "CBC"), new Property("sm4-iv-value", "12345678")));
    }
    
    @Test
    void assertCreateNewInstanceWithoutSM4Key() {
        assertThrows(AlgorithmInitializationException.class, () -> TypedSPILoader.getService(CryptographicAlgorithm.class, "SM4"));
    }
    
    @Test
    void assertCreateNewInstanceWithEmptySM4Key() {
        assertThrows(AlgorithmInitializationException.class, () -> cryptographicAlgorithm.init(PropertiesBuilder.build(new Property("sm4-key-value", ""))));
    }
    
    @Test
    void assertCreateNewInstanceWithEmptyDigestAlgorithm() {
        assertThrows(AlgorithmInitializationException.class, () -> cryptographicAlgorithm.init(
                PropertiesBuilder.build(new Property("sm4-key-value", "123456abc"), new Property("digest-algorithm-name", ""))));
    }
    
    @Test
    void assertEncrypt() {
        assertThat(cryptographicAlgorithm.encrypt("test"), is("Kw5KJtf1ph+z0swq0oosgg=="));
    }
    
    @Test
    void assertEncryptNullValue() {
        assertNull(cryptographicAlgorithm.encrypt(null));
    }
    
    @Test
    void assertDecrypt() {
        assertThat(cryptographicAlgorithm.decrypt("Kw5KJtf1ph+z0swq0oosgg=="), is("test"));
    }
    
    @Test
    void assertDecryptNullValue() {
        assertNull(cryptographicAlgorithm.decrypt(null));
    }
    
    @Test
    void assertEncryptCBC() {
        assertThat(cryptographicAlgorithmCBC.encrypt("test"), is("bYF0Ih8XmgRnIAR3CTsNiw=="));
    }
    
    @Test
    void assertEncryptCBCNullValue() {
        assertNull(cryptographicAlgorithmCBC.encrypt(null));
    }
    
    @Test
    void assertDecryptCBC() {
        assertThat(cryptographicAlgorithmCBC.decrypt("bYF0Ih8XmgRnIAR3CTsNiw=="), is("test"));
    }
    
    @Test
    void assertDecryptCBCNullValue() {
        assertNull(cryptographicAlgorithmCBC.decrypt(null));
    }
    
    @Test
    void assertEncryptCBCLongText() {
        String longText = "This is a longer text to test CBC mode padding and block processing";
        Object encrypted = cryptographicAlgorithmCBC.encrypt(longText);
        assertThat(cryptographicAlgorithmCBC.decrypt(encrypted), is(longText));
    }
    
    @Test
    void assertCBCModeWithDifferentIV() {
        CryptographicAlgorithm cbcWithDifferentIV = TypedSPILoader.getService(CryptographicAlgorithm.class, "SM4",
                PropertiesBuilder.build(new Property("sm4-key-value", "test"), new Property("digest-algorithm-name", "SHA-1"), 
                new Property("sm4-mode", "CBC"), new Property("sm4-iv-value", "87654321")));
        
        String plaintext = "test";
        Object encrypted1 = cryptographicAlgorithmCBC.encrypt(plaintext);
        Object encrypted2 = cbcWithDifferentIV.encrypt(plaintext);
        
        // Different IVs should produce different ciphertext
        assertThat(encrypted1.equals(encrypted2), is(false));
        
        // But both should decrypt correctly
        assertThat(cryptographicAlgorithmCBC.decrypt(encrypted1), is(plaintext));
        assertThat(cbcWithDifferentIV.decrypt(encrypted2), is(plaintext));
    }
    
}
