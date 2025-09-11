# ShardingSphere SPI自动加载问题解决方案

## 问题根源

ShardingSphere使用Java SPI（Service Provider Interface）机制自动发现和加载功能模块。启动时会扫描所有`META-INF/services/`目录下的配置文件，并尝试加载配置的实现类。

### 问题表现
- 启动时报`ClassNotFoundException`
- 即使没有配置某个功能，但SPI文件存在就会尝试加载
- "全家桶"架构导致模块间紧密耦合

## 解决方案总结

我提供了**三层解决方案**：

### 🎯 Level 1: 最小化SPI配置（推荐）

**使用脚本**: `./build-encrypt-minimal.sh`

**核心思路**:
1. 从完整JDBC驱动中提取基础类
2. 重新构建`META-INF/services/`配置，只保留加密相关服务
3. 删除所有不需要的SPI配置文件

**保留的SPI服务**:
```
org.apache.shardingsphere.encrypt.spi.EncryptAlgorithm
org.apache.shardingsphere.infra.rule.builder.database.DatabaseRuleBuilder  
org.apache.shardingsphere.infra.yaml.config.swapper.rule.YamlRuleConfigurationSwapper
org.apache.shardingsphere.infra.rewrite.context.SQLRewriteContextDecorator
org.apache.shardingsphere.infra.merge.engine.ResultProcessEngine
```

**删除的SPI服务**:
```
org.apache.shardingsphere.sharding.*     # 分片功能
org.apache.shardingsphere.readwritesplitting.*  # 读写分离
org.apache.shardingsphere.shadow.*       # 影子库
org.apache.shardingsphere.mask.*         # 数据脱敏  
org.apache.shardingsphere.broadcast.*    # 广播表
org.apache.shardingsphere.sqlfederation.* # SQL联邦查询
org.apache.shardingsphere.globalclock.*  # 全局时钟
org.apache.shardingsphere.logging.*      # 日志功能
```

### 🔧 Level 2: 配置文件优化

**使用文件**: `encrypt-minimal-config.yaml`

**要点**:
- 只配置数据源和加密规则
- 不配置其他功能规则
- 精简属性配置

### 📦 Level 3: 依赖管理优化

如果仍有问题，可以考虑：
1. 使用Maven Shade插件排除不需要的类
2. 自定义ClassLoader隔离
3. 运行时动态配置SPI

## 具体使用步骤

### 步骤1: 构建精简JAR
```bash
./build-encrypt-minimal.sh
```

### 步骤2: 使用精简配置
```yaml
# encrypt-minimal-config.yaml
dataSources:
  primary_ds:
    dataSourceClassName: com.zaxxer.hikari.HikariDataSource
    driverClassName: com.mysql.cj.jdbc.Driver
    jdbcUrl: jdbc:mysql://localhost:3306/your_db
    username: your_user
    password: your_pass

rules:
- !ENCRYPT
  tables:
    your_table:
      columns:
        sensitive_column:
          cipherColumn: sensitive_column_cipher
          encryptorName: aes_encryptor
  encryptors:
    aes_encryptor:
      type: AES
      props:
        aes-key-value: your-32-char-secret-key
```

### 步骤3: Java代码使用
```java
String url = "jdbc:shardingsphere:encrypt-minimal-config.yaml";
Connection conn = DriverManager.getConnection(url);
```

## 技术细节

### SPI机制工作原理
1. JVM启动时扫描classpath中的`META-INF/services/`
2. 读取以接口全限定名命名的文件
3. 文件内容为实现类的全限定名列表
4. 使用`ServiceLoader.load()`加载所有实现类

### 我们的优化策略
1. **精确控制SPI文件内容**：只保留必需的实现类
2. **删除多余SPI文件**：避免加载不需要的服务
3. **保持核心依赖**：确保JDBC驱动基本功能正常

## 预期效果

使用精简版驱动后：
- ✅ 启动速度更快
- ✅ 内存占用更少  
- ✅ 避免类加载错误
- ✅ 专注加密功能
- ✅ 依然支持完整的加密特性（AES、SM4、MD5、SM3）

## 故障排除

如果仍有问题：

1. **检查Java版本**：确保使用Java 8+
2. **验证配置文件**：YAML语法正确
3. **确认数据库连接**：基础连接可用
4. **查看详细日志**：开启`sql-show: true`
5. **逐步验证**：从最简单配置开始测试

## 最佳实践

1. **密钥管理**：不要在配置文件中硬编码密钥
2. **表结构设计**：确保cipher列足够长
3. **索引优化**：在辅助查询列上建索引
4. **性能测试**：验证加解密性能影响
5. **备份策略**：制定密钥轮换和数据迁移方案