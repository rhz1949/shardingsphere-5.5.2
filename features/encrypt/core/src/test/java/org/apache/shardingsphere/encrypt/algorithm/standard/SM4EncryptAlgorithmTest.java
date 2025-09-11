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

package org.apache.shardingsphere.encrypt.algorithm.standard;

import org.apache.shardingsphere.encrypt.spi.EncryptAlgorithm;
import org.apache.shardingsphere.infra.algorithm.core.config.AlgorithmConfiguration;
import org.apache.shardingsphere.infra.algorithm.core.context.AlgorithmSQLContext;
import org.apache.shardingsphere.infra.spi.type.typed.TypedSPILoader;
import org.apache.shardingsphere.test.util.PropertiesBuilder;
import org.apache.shardingsphere.test.util.PropertiesBuilder.Property;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

class SM4EncryptAlgorithmTest {
    
    private EncryptAlgorithm encryptAlgorithm;
    
    private EncryptAlgorithm encryptAlgorithmCBC;
    
    @BeforeEach
    void setUp() {
        encryptAlgorithm = TypedSPILoader.getService(EncryptAlgorithm.class, "SM4", 
                PropertiesBuilder.build(new Property("sm4-key-value", "test"), new Property("digest-algorithm-name", "SHA-1")));
        
        encryptAlgorithmCBC = TypedSPILoader.getService(EncryptAlgorithm.class, "SM4",
                PropertiesBuilder.build(new Property("sm4-key-value", "test"), new Property("digest-algorithm-name", "SHA-1"), 
                new Property("sm4-mode", "CBC"), new Property("sm4-iv-value", "12345678")));
    }
    
    @Test
    void assertEncrypt() {
        String encrypted = String.valueOf(encryptAlgorithm.encrypt("test", mock(AlgorithmSQLContext.class)));
        assertThat(encrypted, is("Kw5KJtf1ph+z0swq0oosgg=="));
    }
    
    @Test
    void assertEncryptNullValue() {
        assertNull(encryptAlgorithm.encrypt(null, mock(AlgorithmSQLContext.class)));
    }
    
    @Test
    void assertDecrypt() {
        Object decrypted = encryptAlgorithm.decrypt("Kw5KJtf1ph+z0swq0oosgg==", mock(AlgorithmSQLContext.class));
        assertThat(decrypted, is("test"));
    }
    
    @Test
    void assertDecryptNullValue() {
        assertNull(encryptAlgorithm.decrypt(null, mock(AlgorithmSQLContext.class)));
    }
    
    @Test
    void assertEncryptDecryptRoundTrip() {
        String plainText = "Hello, ShardingSphere with SM4!";
        String encrypted = String.valueOf(encryptAlgorithm.encrypt(plainText, mock(AlgorithmSQLContext.class)));
        Object decrypted = encryptAlgorithm.decrypt(encrypted, mock(AlgorithmSQLContext.class));
        assertThat(decrypted, is(plainText));
    }
    
    @Test
    void assertEncryptCBC() {
        String encrypted = String.valueOf(encryptAlgorithmCBC.encrypt("test", mock(AlgorithmSQLContext.class)));
        assertThat(encrypted, is("bYF0Ih8XmgRnIAR3CTsNiw=="));
    }
    
    @Test
    void assertDecryptCBC() {
        Object decrypted = encryptAlgorithmCBC.decrypt("bYF0Ih8XmgRnIAR3CTsNiw==", mock(AlgorithmSQLContext.class));
        assertThat(decrypted, is("test"));
    }
    
    @Test
    void assertEncryptCBCNullValue() {
        assertNull(encryptAlgorithmCBC.encrypt(null, mock(AlgorithmSQLContext.class)));
    }
    
    @Test
    void assertDecryptCBCNullValue() {
        assertNull(encryptAlgorithmCBC.decrypt(null, mock(AlgorithmSQLContext.class)));
    }
    
    @Test
    void assertEncryptCBCLongText() {
        String longText = "This is a longer text to test SM4 CBC mode padding and block processing functionality";
        String encrypted = String.valueOf(encryptAlgorithmCBC.encrypt(longText, mock(AlgorithmSQLContext.class)));
        Object decrypted = encryptAlgorithmCBC.decrypt(encrypted, mock(AlgorithmSQLContext.class));
        assertThat(decrypted, is(longText));
    }
    
    @Test
    void assertCBCModeWithDifferentIV() {
        EncryptAlgorithm cbcWithDifferentIV = TypedSPILoader.getService(EncryptAlgorithm.class, "SM4",
                PropertiesBuilder.build(new Property("sm4-key-value", "test"), new Property("digest-algorithm-name", "SHA-1"), 
                new Property("sm4-mode", "CBC"), new Property("sm4-iv-value", "87654321")));
        
        String plaintext = "test";
        String encrypted1 = String.valueOf(encryptAlgorithmCBC.encrypt(plaintext, mock(AlgorithmSQLContext.class)));
        String encrypted2 = String.valueOf(cbcWithDifferentIV.encrypt(plaintext, mock(AlgorithmSQLContext.class)));
        
        assertThat(encrypted1, not(encrypted2));
        
        assertThat(encryptAlgorithmCBC.decrypt(encrypted1, mock(AlgorithmSQLContext.class)), is(plaintext));
        assertThat(cbcWithDifferentIV.decrypt(encrypted2, mock(AlgorithmSQLContext.class)), is(plaintext));
    }
    
    @Test
    void assertEncryptWithDifferentDataTypes() {
        assertThat(encryptAlgorithm.decrypt(encryptAlgorithm.encrypt("123", mock(AlgorithmSQLContext.class)), mock(AlgorithmSQLContext.class)), is("123"));
        assertThat(encryptAlgorithm.decrypt(encryptAlgorithm.encrypt("user@example.com", mock(AlgorithmSQLContext.class)), mock(AlgorithmSQLContext.class)), is("user@example.com"));
        assertThat(encryptAlgorithm.decrypt(encryptAlgorithm.encrypt("中文测试", mock(AlgorithmSQLContext.class)), mock(AlgorithmSQLContext.class)), is("中文测试"));
    }
    
    @Test
    void assertToConfiguration() {
        AlgorithmConfiguration actual = encryptAlgorithm.toConfiguration();
        assertThat(actual.getType(), is("SM4"));
        assertThat(actual.getProps().size(), is(2));
        assertThat(actual.getProps().getProperty("sm4-key-value"), is("test"));
        assertThat(actual.getProps().getProperty("digest-algorithm-name"), is("SHA-1"));
    }
    
    @Test
    void assertGetMetaData() {
        assertTrue(encryptAlgorithm.getMetaData().isSupportDecrypt());
        assertTrue(encryptAlgorithm.getMetaData().isSupportEquivalentFilter());
    }
}
