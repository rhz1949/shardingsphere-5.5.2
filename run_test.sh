#!/bin/bash

echo "=== 编译和运行 SM4/SM3 测试程序 ==="

# 设置工作目录
cd /Users/rhz/Study/project/database_encryption/shardingsphere-5.5.2/features/encrypt/core

# 设置类路径
SM4_CLASSES="../../../infra/algorithm/type/cryptographic/type/sm4/target/classes"
SM3_CLASSES="../../../infra/algorithm/type/message-digest/type/sm3/target/classes"
BOUNCY_JAR=$(find ~/.m2/repository -name "bcprov-*.jar" 2>/dev/null | head -1)
CODEC_JAR=$(find ~/.m2/repository -name "commons-codec-*.jar" 2>/dev/null | head -1)

# 如果找不到依赖JAR，尝试在项目中查找
if [ -z "$BOUNCY_JAR" ]; then
    BOUNCY_JAR=$(find ../../../ -name "*bcprov*.jar" 2>/dev/null | head -1)
fi

if [ -z "$CODEC_JAR" ]; then
    CODEC_JAR=$(find ../../../ -name "*commons-codec*.jar" 2>/dev/null | head -1)
fi

CLASSPATH="$SM4_CLASSES:$SM3_CLASSES:$BOUNCY_JAR:$CODEC_JAR"

echo "类路径设置："
echo "SM4: $SM4_CLASSES"
echo "SM3: $SM3_CLASSES"
echo "BouncyCastle: $BOUNCY_JAR"
echo "Commons Codec: $CODEC_JAR"
echo

# 编译TestRunner.java
echo "正在编译 TestRunner.java..."
javac -cp "$CLASSPATH" TestRunner.java

if [ $? -eq 0 ]; then
    echo "编译成功！"
    echo
    echo "=== 运行测试 ==="
    java -cp ".:$CLASSPATH" TestRunner
else
    echo "编译失败！"
    echo
    echo "尝试替代方案：直接运行已有的测试..."
    echo
    echo "运行 SM4 测试："
    cd ../../../infra/algorithm/type/cryptographic/type/sm4
    mvn test -Dtest=SM4CryptographicAlgorithmTest
    
    echo
    echo "运行 SM3 测试："
    cd ../../../message-digest/type/sm3
    mvn test -Dtest=SM3MessageDigestAlgorithmTest
fi