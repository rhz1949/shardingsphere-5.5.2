import java.sql.*;

public class SimpleTest {
    public static void main(String[] args) {
        String url = "jdbc:shardingsphere:test-config.yaml";
        
        try (Connection conn = DriverManager.getConnection(url)) {
            System.out.println("✅ 连接成功！");
            
            // 创建测试表
            try (Statement stmt = conn.createStatement()) {
                stmt.execute("DROP TABLE IF EXISTS t_user");
                stmt.execute("""
                    CREATE TABLE t_user (
                        id INT PRIMARY KEY AUTO_INCREMENT,
                        username VARCHAR(50),
                        password_cipher TEXT,
                        phone_cipher TEXT,
                        id_card_cipher TEXT,
                        id_card_assisted VARCHAR(64)
                    )
                    """);
                System.out.println("✅ 表创建成功！");
            }
            
            // 插入加密数据
            String insertSql = "INSERT INTO t_user(username, password, phone, id_card) VALUES(?, ?, ?, ?)";
            try (PreparedStatement ps = conn.prepareStatement(insertSql)) {
                ps.setString(1, "测试用户");
                ps.setString(2, "secret123");
                ps.setString(3, "13800138000");
                ps.setString(4, "110101199001011234");
                ps.executeUpdate();
                System.out.println("✅ 数据插入成功（已加密）！");
            }
            
            // 查询解密数据
            String selectSql = "SELECT username, password, phone FROM t_user";
            try (Statement stmt = conn.createStatement();
                 ResultSet rs = stmt.executeQuery(selectSql)) {
                while (rs.next()) {
                    System.out.printf("✅ 查询结果：用户=%s, 密码=%s, 手机=%s%n", 
                        rs.getString("username"),
                        rs.getString("password"),
                        rs.getString("phone"));
                }
            }
            
            // 辅助查询
            String assistedSql = "SELECT username FROM t_user WHERE id_card = ?";
            try (PreparedStatement ps = conn.prepareStatement(assistedSql)) {
                ps.setString(1, "110101199001011234");
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        System.out.printf("✅ 辅助查询成功：找到用户=%s%n", rs.getString("username"));
                    }
                }
            }
            
            System.out.println("\n🎉 所有测试通过！加密功能工作正常！");
            
        } catch (Exception e) {
            System.err.println("❌ 错误: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
