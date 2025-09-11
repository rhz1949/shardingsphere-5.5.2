#!/bin/bash

echo "构建精简版 ShardingSphere 加密 JDBC 驱动"
echo "========================================"

# 创建构建目录
mkdir -p encrypt-jdbc/src/main/java
mkdir -p encrypt-jdbc/src/main/resources

echo "Step 1: 复制必需的 JDBC 驱动类..."
# 复制核心 JDBC 驱动文件
cp -r jdbc/src/main/java/* encrypt-jdbc/src/main/java/ 2>/dev/null || true
cp -r jdbc/src/main/resources/* encrypt-jdbc/src/main/resources/ 2>/dev/null || true

echo "Step 2: 构建加密专用 JDBC 驱动..."
cd encrypt-jdbc
mvn clean package -DskipTests

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ 精简版加密 JDBC 驱动构建成功！"
    echo ""
    echo "生成的文件:"
    ls -la target/*.jar
    
    echo ""
    echo "📦 使用方法:"
    echo "1. 使用 shardingsphere-encrypt-jdbc-5.5.2-all.jar (包含所有依赖)"
    echo "2. JDBC URL: jdbc:shardingsphere:config.yaml"
    echo ""
    echo "📝 配置文件示例 (config.yaml):"
    cat << 'EOF'
dataSources:
  ds0:
    dataSourceClassName: com.zaxxer.hikari.HikariDataSource
    driverClassName: com.mysql.cj.jdbc.Driver
    jdbcUrl: jdbc:mysql://localhost:3306/your_database
    username: your_username
    password: your_password

rules:
- !ENCRYPT
  tables:
    user_table:
      columns:
        password:
          cipherColumn: password_cipher
          encryptorName: aes_encryptor
        phone:
          cipherColumn: phone_cipher  
          encryptorName: aes_encryptor
  encryptors:
    aes_encryptor:
      type: AES
      props:
        aes-key-value: your-secret-key
    sm4_encryptor:
      type: SM4
      props:
        sm4-key: your-sm4-key
        sm4-mode: ECB
        sm4-padding: PKCS7Padding
EOF
    
else
    echo "❌ 构建失败，请检查错误信息"
    exit 1
fi

cd ..