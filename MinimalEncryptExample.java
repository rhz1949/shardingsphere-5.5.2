import java.sql.*;

/**
 * ShardingSphere 最小化加密JDBC驱动使用示例
 * 
 * 使用前确保：
 * 1. shardingsphere-encrypt-minimal-5.5.2.jar 在classpath中
 * 2. MySQL驱动 mysql-connector-java.jar 在classpath中
 * 3. HikariCP连接池 HikariCP.jar 在classpath中
 * 4. encrypt-minimal-config.yaml 配置文件路径正确
 */
public class MinimalEncryptExample {
    
    public static void main(String[] args) {
        // JDBC URL - 指向配置文件
        String url = "jdbc:shardingsphere:encrypt-minimal-config.yaml";
        
        try {
            // 注册驱动（可选，通常会自动注册）
            Class.forName("org.apache.shardingsphere.driver.ShardingSphereDriver");
            
            System.out.println("=== ShardingSphere 加密功能演示 ===\n");
            
            try (Connection conn = DriverManager.getConnection(url)) {
                // 创建测试表
                createTestTable(conn);
                
                // 插入加密数据
                insertEncryptedData(conn);
                
                // 查询解密数据
                queryDecryptedData(conn);
                
                // 辅助查询测试
                assistedQuery(conn);
                
            }
            
        } catch (Exception e) {
            System.err.println("错误: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * 创建测试表
     */
    private static void createTestTable(Connection conn) throws SQLException {
        System.out.println("1. 创建测试表...");
        
        String createTableSql = """
            CREATE TABLE IF NOT EXISTS t_user (
                id BIGINT PRIMARY KEY AUTO_INCREMENT,
                username VARCHAR(50) NOT NULL,
                password_cipher TEXT,           -- 存储AES加密后的密码
                phone_cipher TEXT,             -- 存储SM4加密后的手机号
                id_card_cipher TEXT,           -- 存储AES加密后的身份证
                id_card_assisted VARCHAR(64),  -- 存储MD5哈希用于查询
                email_cipher TEXT,             -- 存储AES加密后的邮箱
                email_assisted VARCHAR(64),    -- 存储SM3哈希用于查询
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """;
            
        try (Statement stmt = conn.createStatement()) {
            stmt.execute("DROP TABLE IF EXISTS t_user");
            stmt.execute(createTableSql);
            System.out.println("   ✅ 表创建成功\n");
        }
    }
    
    /**
     * 插入加密数据
     */
    private static void insertEncryptedData(Connection conn) throws SQLException {
        System.out.println("2. 插入加密数据...");
        
        String insertSql = """
            INSERT INTO t_user(username, password, phone, id_card, email) 
            VALUES(?, ?, ?, ?, ?)
            """;
            
        try (PreparedStatement ps = conn.prepareStatement(insertSql)) {
            // 插入第一条记录
            ps.setString(1, "张三");
            ps.setString(2, "password123");         // 将被AES加密
            ps.setString(3, "13800138000");         // 将被SM4加密
            ps.setString(4, "110101199001011234");  // 将被AES加密，MD5辅助查询
            ps.setString(5, "zhangsan@example.com"); // 将被AES加密，SM3辅助查询
            ps.executeUpdate();
            
            // 插入第二条记录
            ps.setString(1, "李四");
            ps.setString(2, "admin888");
            ps.setString(3, "13900139000");
            ps.setString(4, "110101199002022345");
            ps.setString(5, "lisi@example.com");
            ps.executeUpdate();
            
            System.out.println("   ✅ 数据插入成功（自动加密）\n");
        }
    }
    
    /**
     * 查询解密数据
     */
    private static void queryDecryptedData(Connection conn) throws SQLException {
        System.out.println("3. 查询解密数据...");
        
        String selectSql = "SELECT username, password, phone, email FROM t_user ORDER BY id";
        
        try (Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(selectSql)) {
            
            int count = 0;
            while (rs.next()) {
                count++;
                System.out.printf("   用户%d: %s | 密码: %s | 手机: %s | 邮箱: %s%n",
                    count,
                    rs.getString("username"),
                    rs.getString("password"),    // 自动解密
                    rs.getString("phone"),       // 自动解密
                    rs.getString("email")        // 自动解密
                );
            }
            System.out.println("   ✅ 查询成功（自动解密）\n");
        }
    }
    
    /**
     * 辅助查询测试
     */
    private static void assistedQuery(Connection conn) throws SQLException {
        System.out.println("4. 辅助查询测试...");
        
        // 通过身份证查询（使用辅助查询列）
        String assistedSql = "SELECT username FROM t_user WHERE id_card = ?";
        
        try (PreparedStatement ps = conn.prepareStatement(assistedSql)) {
            ps.setString(1, "110101199001011234"); // 使用原始值查询
            
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    System.out.printf("   根据身份证查询到用户: %s%n", rs.getString("username"));
                }
            }
        }
        
        // 通过邮箱查询
        String emailSql = "SELECT username FROM t_user WHERE email = ?";
        
        try (PreparedStatement ps = conn.prepareStatement(emailSql)) {
            ps.setString(1, "lisi@example.com");
            
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    System.out.printf("   根据邮箱查询到用户: %s%n", rs.getString("username"));
                }
            }
        }
        
        System.out.println("   ✅ 辅助查询成功\n");
    }
}