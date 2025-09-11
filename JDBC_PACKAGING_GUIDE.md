# Apache ShardingSphere JDBC 打包指南

## 项目概述
Apache ShardingSphere 是一款分布式数据库中间件，此项目已包含数据库加密功能。本指南说明如何将项目打包成JDBC驱动。

## 快速打包

### 方式一：使用脚本打包
```bash
./build-jdbc.sh
```

### 方式二：手动打包
```bash
# 构建整个项目
mvn clean install -DskipTests

# 或者只构建JDBC分发包
mvn clean package -DskipTests -Prelease -pl distribution/jdbc -am
```

## 生成的文件

构建完成后，您将得到以下重要文件：

### 核心JDBC驱动
- `jdbc/target/shardingsphere-jdbc-5.5.2.jar` - 核心JDBC驱动JAR
- `jdbc/target/shardingsphere-jdbc-5.5.2-sources.jar` - 源代码JAR

### 完整分发包
- `distribution/jdbc/target/apache-shardingsphere-5.5.2-shardingsphere-jdbc-bin.tar.gz` - 完整分发包

## 使用方法

### 1. 作为单一JAR使用
如果您的应用已经包含了ShardingSphere的依赖，可以直接使用：
```java
// JDBC URL格式
jdbc:shardingsphere:config-file-path
```

### 2. 使用完整分发包
1. 解压 `apache-shardingsphere-5.5.2-shardingsphere-jdbc-bin.tar.gz`
2. 将 `lib/` 目录下的所有JAR文件添加到classpath
3. 使用JDBC连接

### 3. Maven依赖方式
```xml
<dependency>
    <groupId>org.apache.shardingsphere</groupId>
    <artifactId>shardingsphere-jdbc</artifactId>
    <version>5.5.2</version>
</dependency>
```

## 配置示例

### 数据加密配置示例
```yaml
# config.yaml
dataSources:
  ds0:
    dataSourceClassName: com.zaxxer.hikari.HikariDataSource
    driverClassName: com.mysql.cj.jdbc.Driver
    jdbcUrl: jdbc:mysql://localhost:3306/demo_ds_0
    username: root
    password: password

rules:
- !ENCRYPT
  tables:
    t_user:
      columns:
        password:
          plainColumn: password_plain
          cipherColumn: password_cipher
          encryptorName: aes_encryptor
  encryptors:
    aes_encryptor:
      type: AES
      props:
        aes-key-value: 123456
```

### Java代码示例
```java
// 加载配置文件
String configFile = "/path/to/config.yaml";
String jdbcUrl = "jdbc:shardingsphere:" + configFile;

// 创建连接
Connection conn = DriverManager.getConnection(jdbcUrl);

// 使用连接进行数据库操作
PreparedStatement stmt = conn.prepareStatement("SELECT * FROM t_user WHERE id = ?");
stmt.setInt(1, 1);
ResultSet rs = stmt.executeQuery();
```

## 项目特性

此版本包含以下增强的加密功能：
- SM2、SM3、SM4国密算法支持
- AES加密算法
- 自动加解密
- 透明化数据加密

## 依赖的数据库驱动

项目已包含以下数据库驱动：
- MySQL: mysql-connector-j
- PostgreSQL: postgresql
- SQL Server: mssql-jdbc  
- H2: h2database

## 故障排除

### 常见问题
1. **ClassNotFoundException**: 确保所有相关JAR文件都在classpath中
2. **配置文件找不到**: 检查配置文件路径是否正确
3. **加密算法不支持**: 确认使用的加密算法在配置中正确定义

### 日志配置
在classpath中添加logback.xml来配置日志：
```xml
<configuration>
    <appender name="STDOUT" class="ch.qos.logback.core.ConsoleAppender">
        <encoder>
            <pattern>%d{HH:mm:ss.SSS} [%thread] %-5level %logger{36} - %msg%n</pattern>
        </encoder>
    </appender>
    
    <logger name="org.apache.shardingsphere" level="INFO"/>
    
    <root level="INFO">
        <appender-ref ref="STDOUT"/>
    </root>
</configuration>
```

## 更多信息

- 官方文档: https://shardingsphere.apache.org/
- GitHub: https://github.com/apache/shardingsphere
- 版本: 5.5.2