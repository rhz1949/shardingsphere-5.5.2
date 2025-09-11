# ShardingSphere 仅加密功能使用指南

## 快速解决方案

由于ShardingSphere架构的复杂性，推荐使用以下三种方案：

### 方案1: 使用完整JDBC驱动（推荐）
```bash
# 使用现有的完整JDBC驱动，只配置加密功能
cp jdbc/target/shardingsphere-jdbc-5.5.2.jar ./shardingsphere-encrypt-jdbc.jar
```

**优点**: 稳定可靠，功能完整
**缺点**: JAR包较大（但未使用的功能不会影响性能）

### 方案2: 修复依赖后构建
```bash
# 先尝试修复后的配置
cd encrypt-jdbc
mvn clean package -DskipTests
```

### 方案3: 手动提取（实验性）
```bash
./build-encrypt-only.sh
```

## 仅加密配置示例

### 基础加密配置
```yaml
# config.yaml
dataSources:
  ds0:
    dataSourceClassName: com.zaxxer.hikari.HikariDataSource
    driverClassName: com.mysql.cj.jdbc.Driver
    jdbcUrl: jdbc:mysql://localhost:3306/your_db
    username: your_username
    password: your_password

rules:
- !ENCRYPT
  tables:
    user_info:
      columns:
        # 密码字段加密
        password:
          cipherColumn: password_cipher
          encryptorName: aes_encryptor
        # 手机号加密
        phone:
          cipherColumn: phone_cipher
          encryptorName: sm4_encryptor
        # 身份证加密（带辅助查询）
        id_card:
          cipherColumn: id_card_cipher
          assistedQueryColumn: id_card_assisted
          encryptorName: aes_encryptor
          assistedQueryEncryptorName: md5_encryptor
          
  encryptors:
    # AES加密器
    aes_encryptor:
      type: AES
      props:
        aes-key-value: your-32-character-secret-key-here
    
    # SM4国密加密器
    sm4_encryptor:
      type: SM4
      props:
        sm4-key: your-16-byte-sm4-key
        sm4-mode: ECB
        sm4-padding: PKCS7Padding
    
    # MD5辅助查询加密器
    md5_encryptor:
      type: MD5
```

### Java使用示例
```java
public class EncryptExample {
    public static void main(String[] args) throws SQLException {
        // 加载配置
        String url = "jdbc:shardingsphere:config.yaml";
        
        try (Connection conn = DriverManager.getConnection(url)) {
            // 插入数据 - 自动加密
            String insertSql = "INSERT INTO user_info(username, password, phone, id_card) VALUES(?, ?, ?, ?)";
            try (PreparedStatement ps = conn.prepareStatement(insertSql)) {
                ps.setString(1, "张三");
                ps.setString(2, "123456");        // 将被AES加密
                ps.setString(3, "13800138000");   // 将被SM4加密
                ps.setString(4, "110101199001011234"); // 将被AES加密，MD5辅助查询
                ps.executeUpdate();
            }
            
            // 查询数据 - 自动解密
            String selectSql = "SELECT username, password, phone FROM user_info WHERE username = ?";
            try (PreparedStatement ps = conn.prepareStatement(selectSql)) {
                ps.setString(1, "张三");
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        System.out.println("用户名: " + rs.getString("username"));
                        System.out.println("密码: " + rs.getString("password"));    // 自动解密
                        System.out.println("手机: " + rs.getString("phone"));       // 自动解密
                    }
                }
            }
            
            // 辅助查询（可以基于加密字段查询）
            String assistedSql = "SELECT username FROM user_info WHERE id_card = ?";
            try (PreparedStatement ps = conn.prepareStatement(assistedSql)) {
                ps.setString(1, "110101199001011234"); // 使用原始值查询
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        System.out.println("找到用户: " + rs.getString("username"));
                    }
                }
            }
        }
    }
}
```

## 数据库表结构

```sql
CREATE TABLE user_info (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) NOT NULL,
    password_cipher VARCHAR(200),        -- 存储加密后的密码
    phone_cipher VARCHAR(200),           -- 存储加密后的手机号
    id_card_cipher VARCHAR(200),         -- 存储加密后的身份证
    id_card_assisted VARCHAR(200),       -- 辅助查询字段
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## 支持的加密算法

- **AES**: 高级加密标准，安全性高
- **SM4**: 国密算法，符合国产化要求
- **MD5**: 单向哈希，用于辅助查询
- **SM3**: 国密哈希算法

## 性能优化建议

1. **选择合适的加密算法**：AES性能较好，SM4符合国密要求
2. **使用辅助查询列**：对需要WHERE查询的字段配置辅助查询
3. **合理设计索引**：在辅助查询列上建立索引
4. **批量操作**：使用批量插入/更新提高性能

## 故障排除

1. **密钥长度错误**: AES需要16/24/32字节密钥，SM4需要16字节
2. **配置文件路径**: 确保config.yaml路径正确
3. **数据库表结构**: 确保cipher列足够长存储加密数据
4. **字符编码**: 建议使用UTF-8编码