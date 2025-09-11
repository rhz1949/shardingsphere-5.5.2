#!/bin/bash

echo "构建最小化ShardingSphere加密JDBC驱动"
echo "====================================="

# 检查项目是否已构建
if [ ! -f "jdbc/target/shardingsphere-jdbc-5.5.2.jar" ]; then
    echo "Step 1: 构建完整项目..."
    mvn clean install -DskipTests -q
    if [ $? -ne 0 ]; then
        echo "❌ 项目构建失败"
        exit 1
    fi
fi

echo "Step 2: 创建精简版JAR..."

# 创建工作目录
WORK_DIR="encrypt-minimal"
rm -rf $WORK_DIR
mkdir -p $WORK_DIR
cd $WORK_DIR

# 解压核心JDBC驱动
echo "  - 解压JDBC核心..."
jar xf ../jdbc/target/shardingsphere-jdbc-5.5.2.jar

# 创建精简的SPI服务配置目录
mkdir -p META-INF/services

echo "Step 3: 配置最小化SPI服务..."

# 只保留加密算法服务
cat > META-INF/services/org.apache.shardingsphere.encrypt.spi.EncryptAlgorithm << 'EOF'
# 仅保留加密算法
org.apache.shardingsphere.encrypt.algorithm.standard.AESEncryptAlgorithm
org.apache.shardingsphere.encrypt.algorithm.assisted.MD5AssistedEncryptAlgorithm
org.apache.shardingsphere.encrypt.algorithm.standard.SM4EncryptAlgorithm
org.apache.shardingsphere.encrypt.algorithm.assisted.SM3AssistedEncryptAlgorithm
EOF

# 保留数据库类型支持（必需）
cp META-INF/services/org.apache.shardingsphere.infra.database.core.type.DatabaseType META-INF/services/org.apache.shardingsphere.infra.database.core.type.DatabaseType.bak 2>/dev/null || true

# 保留加密规则构建器（必需）
cat > META-INF/services/org.apache.shardingsphere.infra.rule.builder.database.DatabaseRuleBuilder << 'EOF'
# 只保留加密规则构建器
org.apache.shardingsphere.encrypt.rule.EncryptRuleBuilder
EOF

# 保留加密YAML配置交换器（必需）
cat > META-INF/services/org.apache.shardingsphere.infra.yaml.config.swapper.rule.YamlRuleConfigurationSwapper << 'EOF'
# 只保留加密配置交换器
org.apache.shardingsphere.encrypt.yaml.swapper.YamlEncryptRuleConfigurationSwapper
EOF

# 保留加密SQL重写装饰器（必需）
cat > META-INF/services/org.apache.shardingsphere.infra.rewrite.context.SQLRewriteContextDecorator << 'EOF'
# 只保留加密SQL重写
org.apache.shardingsphere.encrypt.rewrite.EncryptSQLRewriteContextDecorator
EOF

# 保留加密结果处理引擎（必需）
cat > META-INF/services/org.apache.shardingsphere.infra.merge.engine.ResultProcessEngine << 'EOF'
# 只保留加密结果处理
org.apache.shardingsphere.encrypt.merge.EncryptResultProcessEngine
EOF

# 删除不需要的SPI服务文件（避免自动加载不存在的类）
echo "Step 4: 清理不需要的SPI配置..."
rm -f META-INF/services/org.apache.shardingsphere.sharding.* 2>/dev/null
rm -f META-INF/services/org.apache.shardingsphere.readwritesplitting.* 2>/dev/null  
rm -f META-INF/services/org.apache.shardingsphere.shadow.* 2>/dev/null
rm -f META-INF/services/org.apache.shardingsphere.mask.* 2>/dev/null
rm -f META-INF/services/org.apache.shardingsphere.broadcast.* 2>/dev/null
rm -f META-INF/services/org.apache.shardingsphere.sqlfederation.* 2>/dev/null
rm -f META-INF/services/org.apache.shardingsphere.globalclock.* 2>/dev/null
rm -f META-INF/services/org.apache.shardingsphere.logging.* 2>/dev/null

# 创建自定义MANIFEST
cat > META-INF/MANIFEST.MF << 'EOF'
Manifest-Version: 1.0
Implementation-Title: ShardingSphere Encrypt-Only JDBC
Implementation-Version: 5.5.2-encrypt-minimal
Implementation-Vendor: Apache ShardingSphere
Main-Class: org.apache.shardingsphere.driver.ShardingSphereDriver
EOF

echo "Step 5: 重新打包..."
jar cfm ../shardingsphere-encrypt-minimal-5.5.2.jar META-INF/MANIFEST.MF -C . .

cd ..
rm -rf $WORK_DIR

if [ -f "shardingsphere-encrypt-minimal-5.5.2.jar" ]; then
    echo ""
    echo "✅ 最小化加密JDBC驱动构建成功！"
    
    # 显示文件大小对比
    if [ -f "jdbc/target/shardingsphere-jdbc-5.5.2.jar" ]; then
        ORIGINAL_SIZE=$(ls -lh jdbc/target/shardingsphere-jdbc-5.5.2.jar | awk '{print $5}')
        MINIMAL_SIZE=$(ls -lh shardingsphere-encrypt-minimal-5.5.2.jar | awk '{print $5}')
        echo ""
        echo "📊 文件大小对比:"
        echo "  原版: $ORIGINAL_SIZE"
        echo "  精简版: $MINIMAL_SIZE"
    fi
    
    echo ""
    echo "🎯 精简版特点:"
    echo "  ✅ 仅包含数据加密功能"
    echo "  ✅ 移除了分片、读写分离等功能"
    echo "  ✅ 精简的SPI配置，避免启动错误"
    echo "  ✅ 支持AES、SM4、MD5、SM3算法"
    
    echo ""
    echo "📖 使用指南:"
    echo "1. 将 shardingsphere-encrypt-minimal-5.5.2.jar 添加到项目依赖"
    echo "2. 创建配置文件，只配置加密规则"
    echo "3. 使用 jdbc:shardingsphere:config.yaml 连接"
    
else
    echo "❌ 构建失败"
    exit 1
fi