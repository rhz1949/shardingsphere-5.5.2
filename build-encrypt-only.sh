#!/bin/bash

echo "构建仅包含加密功能的ShardingSphere JDBC驱动"
echo "============================================="

echo "Step 1: 构建完整项目..."
mvn clean install -DskipTests -q

if [ $? -ne 0 ]; then
    echo "❌ 项目构建失败"
    exit 1
fi

echo "Step 2: 创建加密专用JAR包..."

# 创建临时目录
TEMP_DIR="encrypt-only-jdbc"
mkdir -p $TEMP_DIR
cd $TEMP_DIR

# 创建META-INF目录
mkdir -p META-INF/services

# 解压必需的JAR包
echo "提取核心功能..."
jar xf ../jdbc/target/shardingsphere-jdbc-5.5.2.jar

# 提取加密相关的类
echo "提取加密功能..."
jar xf ../features/encrypt/core/target/shardingsphere-encrypt-core-5.5.2.jar
jar xf ../features/encrypt/api/target/shardingsphere-encrypt-api-5.5.2.jar

# 提取加密算法
echo "提取加密算法..."
jar xf ../infra/algorithm/type/cryptographic/type/aes/target/shardingsphere-infra-algorithm-cryptographic-aes-5.5.2.jar
jar xf ../infra/algorithm/type/cryptographic/type/sm4/target/shardingsphere-infra-algorithm-cryptographic-sm4-5.5.2.jar
jar xf ../infra/algorithm/type/message-digest/type/md5/target/shardingsphere-infra-algorithm-message-digest-md5-5.5.2.jar
jar xf ../infra/algorithm/type/message-digest/type/sm3/target/shardingsphere-infra-algorithm-message-digest-sm3-5.5.2.jar

# 创建一个简化的服务配置
cat > META-INF/services/org.apache.shardingsphere.encrypt.spi.EncryptAlgorithm << 'EOF'
org.apache.shardingsphere.infra.algorithm.cryptographic.aes.AESEncryptAlgorithm
org.apache.shardingsphere.infra.algorithm.cryptographic.sm4.SM4CryptographicAlgorithm
org.apache.shardingsphere.encrypt.algorithm.assisted.MD5AssistedEncryptAlgorithm
org.apache.shardingsphere.encrypt.algorithm.assisted.SM3AssistedEncryptAlgorithm
EOF

# 创建MANIFEST.MF
cat > META-INF/MANIFEST.MF << 'EOF'
Manifest-Version: 1.0
Main-Class: org.apache.shardingsphere.driver.ShardingSphereDriver
EOF

# 打包成JAR
echo "Step 3: 打包JAR文件..."
jar cfm ../shardingsphere-encrypt-only-${VERSION:-5.5.2}.jar META-INF/MANIFEST.MF -C . .

cd ..
rm -rf $TEMP_DIR

if [ -f "shardingsphere-encrypt-only-${VERSION:-5.5.2}.jar" ]; then
    echo ""
    echo "✅ 加密专用JDBC驱动构建成功！"
    echo ""
    echo "📦 生成的文件:"
    ls -la shardingsphere-encrypt-only-*.jar
    
    echo ""
    echo "🎯 这个JAR包仅包含:"
    echo "  ✓ 数据库加密/解密功能"
    echo "  ✓ AES、SM4、MD5、SM3算法"
    echo "  ✓ JDBC核心驱动"
    echo "  ✗ 分片功能 (已移除)"
    echo "  ✗ 读写分离 (已移除)"
    echo "  ✗ 影子库 (已移除)"
    echo "  ✗ 数据脱敏 (已移除)"
    
    echo ""
    echo "📝 使用示例:"
    cat << 'USAGE'
    
# 1. 将JAR添加到项目依赖
# 2. 创建配置文件 config.yaml:

dataSources:
  ds0:
    dataSourceClassName: com.zaxxer.hikari.HikariDataSource
    driverClassName: com.mysql.cj.jdbc.Driver
    jdbcUrl: jdbc:mysql://localhost:3306/demo
    username: root
    password: password

rules:
- !ENCRYPT
  tables:
    t_user:
      columns:
        password:
          cipherColumn: password_cipher
          encryptorName: aes_encryptor
        email:
          cipherColumn: email_cipher
          encryptorName: aes_encryptor
  encryptors:
    aes_encryptor:
      type: AES
      props:
        aes-key-value: your-secret-key-here

# 3. Java代码:
String url = "jdbc:shardingsphere:config.yaml";
Connection conn = DriverManager.getConnection(url);
USAGE

else
    echo "❌ 构建失败"
    exit 1
fi