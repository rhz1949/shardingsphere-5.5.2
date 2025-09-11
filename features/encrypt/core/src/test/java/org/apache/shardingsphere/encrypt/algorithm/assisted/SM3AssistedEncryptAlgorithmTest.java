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

package org.apache.shardingsphere.encrypt.algorithm.assisted;

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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.Mockito.mock;

class SM3AssistedEncryptAlgorithmTest {
    
    private EncryptAlgorithm encryptAlgorithm;
    
    private EncryptAlgorithm encryptAlgorithmWithSalt;
    
    @BeforeEach
    void setUp() {
        encryptAlgorithm = TypedSPILoader.getService(EncryptAlgorithm.class, "SM3");
        encryptAlgorithmWithSalt = TypedSPILoader.getService(EncryptAlgorithm.class, "SM3", 
                PropertiesBuilder.build(new Property("salt", "mysalt123")));
    }
    
    @Test
    void assertEncrypt() {
        String encrypted = String.valueOf(encryptAlgorithm.encrypt("test", mock(AlgorithmSQLContext.class)));
        assertThat(encrypted, is("VeEukWUNL+xW7HTh0+Tdv84u86ZYkMKhns+IowfnaiM="));
    }
    
    @Test
    void assertEncryptNullValue() {
        assertNull(encryptAlgorithm.encrypt(null, mock(AlgorithmSQLContext.class)));
    }
    
    @Test
    void assertEncryptWithSalt() {
        String encrypted = String.valueOf(encryptAlgorithmWithSalt.encrypt("test", mock(AlgorithmSQLContext.class)));
        String encryptedWithoutSalt = String.valueOf(encryptAlgorithm.encrypt("test", mock(AlgorithmSQLContext.class)));
        assertThat(encrypted, not(encryptedWithoutSalt));
    }
    
    @Test
    void assertEncryptSameInputSameOutput() {
        String encrypted1 = String.valueOf(encryptAlgorithm.encrypt("test", mock(AlgorithmSQLContext.class)));
        String encrypted2 = String.valueOf(encryptAlgorithm.encrypt("test", mock(AlgorithmSQLContext.class)));
        assertThat(encrypted1, is(encrypted2));
    }
    
    @Test
    void assertEncryptDifferentInputDifferentOutput() {
        String encrypted1 = String.valueOf(encryptAlgorithm.encrypt("test1", mock(AlgorithmSQLContext.class)));
        String encrypted2 = String.valueOf(encryptAlgorithm.encrypt("test2", mock(AlgorithmSQLContext.class)));
        assertThat(encrypted1, not(encrypted2));
    }
    
    @Test
    void assertEncryptWithDifferentDataTypes() {
        String encryptedString = String.valueOf(encryptAlgorithm.encrypt("hello", mock(AlgorithmSQLContext.class)));
        String encryptedNumber = String.valueOf(encryptAlgorithm.encrypt("123456", mock(AlgorithmSQLContext.class)));
        String encryptedEmail = String.valueOf(encryptAlgorithm.encrypt("user@example.com", mock(AlgorithmSQLContext.class)));
        String encryptedChinese = String.valueOf(encryptAlgorithm.encrypt("中文测试", mock(AlgorithmSQLContext.class)));
        
        assertThat(encryptedString, not(encryptedNumber));
        assertThat(encryptedNumber, not(encryptedEmail));
        assertThat(encryptedEmail, not(encryptedChinese));
    }
    
    @Test
    void assertEncryptEmptyString() {
        String encrypted = String.valueOf(encryptAlgorithm.encrypt("", mock(AlgorithmSQLContext.class)));
        assertThat(encrypted, is("GrIdg1XPoX+OYRlIMegajyK+yMco/vt0ftA161CCqis="));
    }
    
    @Test
    void assertEncryptLongText() {
        String longText = "This is a very long text to test SM3 hash algorithm functionality with various characters and symbols!@#$%^&*()";
        String encrypted = String.valueOf(encryptAlgorithm.encrypt(longText, mock(AlgorithmSQLContext.class)));
        assertTrue(encrypted.length() > 0);
        
        String encrypted2 = String.valueOf(encryptAlgorithm.encrypt(longText, mock(AlgorithmSQLContext.class)));
        assertThat(encrypted, is(encrypted2));
    }
    
    @Test
    void assertDecrypt() {
        assertThrows(UnsupportedOperationException.class, () -> encryptAlgorithm.decrypt("test", mock(AlgorithmSQLContext.class)));
    }
    
    @Test
    void assertToConfiguration() {
        AlgorithmConfiguration actual = encryptAlgorithm.toConfiguration();
        assertThat(actual.getType(), is("SM3"));
        assertTrue(actual.getProps().isEmpty());
    }
    
    @Test
    void assertToConfigurationWithSalt() {
        AlgorithmConfiguration actual = encryptAlgorithmWithSalt.toConfiguration();
        assertThat(actual.getType(), is("SM3"));
        assertThat(actual.getProps().size(), is(1));
        assertThat(actual.getProps().getProperty("salt"), is("mysalt123"));
    }
    
    @Test
    void assertGetMetaData() {
        assertFalse(encryptAlgorithm.getMetaData().isSupportDecrypt());
        assertTrue(encryptAlgorithm.getMetaData().isSupportEquivalentFilter());
        assertFalse(encryptAlgorithm.getMetaData().isSupportLike());
    }
}
