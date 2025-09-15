import java.sql.*;

public class SimpleDemo {
    public static void main(String[] args) {
        System.out.println("🚀 ShardingSphere 精简版加密驱动演示");
        System.out.println("=====================================\n");
        
        // 手动注册JDBC驱动
        Class.forName("org.apache.shardingsphere.driver.ShardingSphereDriver");
        
        String url = "jdbc:shardingsphere:simple-config.yaml";
        
        try {
            Connection conn = DriverManager.getConnection(url);
            System.out.println("✅ 数据库连接成功");
            
            // 创建表
            String createSql = "CREATE TABLE demo_table (" +
                "id INT PRIMARY KEY, " +
                "name VARCHAR(50), " +
                "secret_info_cipher TEXT" +
                ")";
            
            try (Statement stmt = conn.createStatement()) {
                stmt.execute("DROP TABLE IF EXISTS demo_table");
                stmt.execute(createSql);
                System.out.println("✅ 测试表创建成功");
            }
            
            // 插入加密数据
            String insertSql = "INSERT INTO demo_table(id, name, secret_info) VALUES(?, ?, ?)";
            try (PreparedStatement ps = conn.prepareStatement(insertSql)) {
                ps.setInt(1, 1);
                ps.setString(2, "用户1");
                ps.setString(3, "这是机密信息123456");
                ps.executeUpdate();
                
                ps.setInt(1, 2);
                ps.setString(2, "用户2");
                ps.setString(3, "另一个秘密数据abcdef");
                ps.executeUpdate();
                
                System.out.println("✅ 测试数据插入成功（已自动加密）");
            }
            
            // 查询解密数据
            String selectSql = "SELECT id, name, secret_info FROM demo_table ORDER BY id";
            try (Statement stmt = conn.createStatement();
                 ResultSet rs = stmt.executeQuery(selectSql)) {
                
                System.out.println("\n📋 查询结果（自动解密）:");
                while (rs.next()) {
                    System.out.printf("   ID: %d | 姓名: %s | 机密信息: %s%n",
                        rs.getInt("id"),
                        rs.getString("name"),
                        rs.getString("secret_info")
                    );
                }
            }
            
            // 显示实际存储的加密数据
            String rawSql = "SELECT id, name, secret_info_cipher FROM demo_table ORDER BY id";
            try (Statement stmt = conn.createStatement();
                 ResultSet rs = stmt.executeQuery(rawSql)) {
                
                System.out.println("\n🔒 数据库中实际存储的加密数据:");
                while (rs.next()) {
                    String encrypted = rs.getString("secret_info_cipher");
                    String preview = encrypted.length() > 20 ? 
                        encrypted.substring(0, 20) + "..." : encrypted;
                    System.out.printf("   ID: %d | 姓名: %s | 加密数据: %s%n",
                        rs.getInt("id"),
                        rs.getString("name"),
                        preview
                    );
                }
            }
            
            System.out.println("\n🎉 演示完成！加密功能工作正常！");
            System.out.println("\n✨ 特性展示:");
            System.out.println("   • 透明加密：插入时自动加密");
            System.out.println("   • 透明解密：查询时自动解密");
            System.out.println("   • 数据安全：实际存储为加密数据");
            System.out.println("   • 应用无感：无需修改业务代码");
            
            conn.close();
            
        } catch (Exception e) {
            System.err.println("❌ 演示失败: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
