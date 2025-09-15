#!/bin/bash

# 简化演示脚本 - 避免外部依赖下载问题
# ========================================

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

print_step() {
    echo -e "\n${BLUE}=== $1 ===${NC}\n"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${CYAN}ℹ️  $1${NC}"
}

echo -e "${BLUE}ShardingSphere 精简版加密JDBC驱动简化演示${NC}\n"

# 检查基础环境
print_step "检查基础环境"
if ! command -v java &> /dev/null; then
    print_error "未找到Java"; exit 1
fi
if ! command -v mvn &> /dev/null; then
    print_error "未找到Maven"; exit 1
fi
print_success "环境检查通过"

# 检查是否在正确目录
if [ ! -f "pom.xml" ]; then
    print_error "请在ShardingSphere项目根目录下运行"
    exit 1
fi

# 构建完整项目（如果需要）
if [ ! -f "jdbc/target/shardingsphere-jdbc-5.5.2.jar" ]; then
    print_step "构建ShardingSphere项目"
    print_info "这可能需要几分钟..."
    mvn clean install -DskipTests -q
    print_success "项目构建完成"
fi

# 构建精简版驱动
print_step "构建精简版加密驱动"
./build-encrypt-minimal.sh

# 创建简单演示
print_step "创建简单演示"
mkdir -p simple-demo
cd simple-demo

# 复制驱动
cp ../shardingsphere-encrypt-minimal-5.5.2.jar .

# 使用Maven复制H2依赖（从本地仓库）
print_info "从Maven仓库获取H2数据库..."
H2_JAR=$(find ~/.m2/repository/com/h2database/h2 -name "*.jar" | head -1)
if [ -n "$H2_JAR" ] && [ -f "$H2_JAR" ]; then
    cp "$H2_JAR" h2.jar
    print_success "H2数据库已复制"
else
    print_warning "未找到H2数据库，请确保已执行过完整构建"
    # 尝试从项目中复制
    find .. -name "h2-*.jar" -exec cp {} h2.jar \; 2>/dev/null || true
fi

# 创建简单的配置文件
cat > simple-config.yaml << 'EOF'
dataSources:
  ds:
    dataSourceClassName: org.h2.jdbcx.JdbcDataSource
    URL: jdbc:h2:mem:demo;MODE=MySQL
    user: sa
    password: ""

rules:
- !ENCRYPT
  tables:
    demo_table:
      columns:
        secret_info:
          cipherColumn: secret_info_cipher
          encryptorName: demo_aes
  encryptors:
    demo_aes:
      type: AES
      props:
        aes-key-value: demo12345678901234567890123456789012

props:
  sql-show: false
EOF

# 创建简单的测试程序
cat > SimpleDemo.java << 'EOF'
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
EOF

# 编译并运行
print_step "编译并运行演示"

if [ -f "h2.jar" ]; then
    CLASSPATH="shardingsphere-encrypt-minimal-5.5.2.jar:h2.jar"
else
    print_warning "H2数据库JAR不存在，请手动下载或从完整构建中复制"
    CLASSPATH="shardingsphere-encrypt-minimal-5.5.2.jar"
fi

print_info "编译演示程序..."
if javac -cp "$CLASSPATH" SimpleDemo.java 2>/dev/null; then
    print_success "编译成功"
    
    print_info "运行演示程序...\n"
    echo "=========================================="
    java -cp ".:$CLASSPATH" SimpleDemo
    echo "=========================================="
    
    print_success "\n演示运行完成"
    
    # 显示文件信息
    print_step "构建结果"
    echo "生成的文件:"
    ls -lh shardingsphere-encrypt-minimal-5.5.2.jar | awk '{print "  📦 精简版驱动: " $9 " (" $5 ")"}'
    if [ -f "../jdbc/target/shardingsphere-jdbc-5.5.2.jar" ]; then
        ls -lh ../jdbc/target/shardingsphere-jdbc-5.5.2.jar | awk '{print "  📦 完整版驱动: " $9 " (" $5 ")"}'
    fi
    
    echo -e "\n配置文件:"
    echo "  📄 simple-config.yaml - 演示配置"
    echo "  📄 SimpleDemo.java - 演示代码"
    
else
    print_error "编译失败，请检查依赖是否正确"
    echo "当前classpath: $CLASSPATH"
    echo "可用JAR文件:"
    ls -la *.jar 2>/dev/null || echo "  无JAR文件"
fi

# 清理询问
echo
read -p "是否保留演示文件？(y/N): " -n 1 -r
echo
cd ..
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    rm -rf simple-demo
    print_info "演示文件已清理"
else
    print_info "演示文件保留在 simple-demo/ 目录"
fi

print_success "简化演示完成！"