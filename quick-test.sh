#!/bin/bash

# 快速测试脚本 - 仅验证精简版驱动是否正常工作
# ================================================

set -e

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}ShardingSphere 精简版加密驱动快速测试${NC}\n"

# 检查文件是否存在
if [ ! -f "shardingsphere-encrypt-minimal-5.5.2.jar" ]; then
    echo -e "${RED}❌ 未找到精简版驱动，请先运行 ./build-encrypt-minimal.sh${NC}"
    exit 1
fi

# 创建临时测试目录
mkdir -p temp-test
cd temp-test

# 复制必要文件
cp ../shardingsphere-encrypt-minimal-5.5.2.jar .

# 下载H2数据库（用于测试）
if [ ! -f "h2.jar" ]; then
    echo "下载H2数据库..."
    curl -s -L -o h2.jar \
        "https://repo1.maven.org/maven2/com/h2database/h2/2.2.224/h2-2.2.224.jar" || {
        echo -e "${RED}❌ 无法下载H2数据库${NC}"
        exit 1
    }
fi

# 创建测试配置
cat > quick-test-config.yaml << 'EOF'
dataSources:
  ds:
    dataSourceClassName: org.h2.jdbcx.JdbcDataSource
    URL: jdbc:h2:mem:test;MODE=MySQL
    user: sa
    password: ""

rules:
- !ENCRYPT
  tables:
    test_table:
      columns:
        secret_data:
          cipherColumn: secret_data_cipher
          encryptorName: test_aes
  encryptors:
    test_aes:
      type: AES
      props:
        aes-key-value: test1234test1234test1234test1234

props:
  sql-show: true
EOF

# 创建测试程序
cat > QuickTest.java << 'EOF'
import java.sql.*;

public class QuickTest {
    public static void main(String[] args) {
        String url = "jdbc:shardingsphere:quick-test-config.yaml";
        
        try (Connection conn = DriverManager.getConnection(url)) {
            System.out.println("✅ 连接建立成功");
            
            // 创建表
            try (Statement stmt = conn.createStatement()) {
                stmt.execute("CREATE TABLE test_table (id INT, secret_data_cipher TEXT)");
                System.out.println("✅ 表创建成功");
            }
            
            // 插入数据
            String insertSql = "INSERT INTO test_table(id, secret_data) VALUES(?, ?)";
            try (PreparedStatement ps = conn.prepareStatement(insertSql)) {
                ps.setInt(1, 1);
                ps.setString(2, "这是加密的秘密数据");
                ps.executeUpdate();
                System.out.println("✅ 数据插入成功（已加密）");
            }
            
            // 查询数据
            try (Statement stmt = conn.createStatement();
                 ResultSet rs = stmt.executeQuery("SELECT id, secret_data FROM test_table")) {
                while (rs.next()) {
                    System.out.printf("✅ 查询成功 - ID: %d, 解密数据: %s%n", 
                        rs.getInt("id"), rs.getString("secret_data"));
                }
            }
            
            System.out.println("\n🎉 快速测试通过！精简版驱动工作正常！");
            
        } catch (Exception e) {
            System.err.println("❌ 测试失败: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}
EOF

# 编译和运行
echo "编译测试程序..."
if javac -cp "shardingsphere-encrypt-minimal-5.5.2.jar:h2.jar" QuickTest.java; then
    echo -e "${GREEN}✅ 编译成功${NC}"
else
    echo -e "${RED}❌ 编译失败${NC}"
    exit 1
fi

echo -e "\n${BLUE}运行测试...${NC}\n"
echo "==================== 测试输出 ===================="
if java -cp ".:shardingsphere-encrypt-minimal-5.5.2.jar:h2.jar" QuickTest; then
    echo "=================================================="
    echo -e "\n${GREEN}✅ 快速测试完成！精简版加密驱动工作正常！${NC}"
else
    echo "=================================================="
    echo -e "\n${RED}❌ 测试失败${NC}"
    exit 1
fi

# 清理
cd ..
rm -rf temp-test

echo -e "\n${BLUE}测试环境已清理${NC}"