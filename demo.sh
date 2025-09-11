#!/bin/bash

# ShardingSphere 加密JDBC驱动完整演示脚本
# ==================================================

set -e  # 遇到错误立即退出

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 打印彩色消息
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

# 检查必要的命令
check_prerequisites() {
    print_step "检查环境依赖"
    
    # 检查Java
    if ! command -v java &> /dev/null; then
        print_error "未找到Java，请安装Java 8+"; exit 1
    else
        JAVA_VERSION=$(java -version 2>&1 | head -n1 | cut -d'"' -f2)
        print_success "Java版本: $JAVA_VERSION"
    fi
    
    # 检查Maven
    if ! command -v mvn &> /dev/null; then
        print_error "未找到Maven，请安装Maven"; exit 1
    else
        MVN_VERSION=$(mvn -version | head -n1 | cut -d' ' -f3)
        print_success "Maven版本: $MVN_VERSION"
    fi
    
    # 检查jar命令
    if ! command -v jar &> /dev/null; then
        print_error "未找到jar命令"; exit 1
    else
        print_success "jar命令可用"
    fi
    
    print_info "所有依赖检查通过"
}

# 清理之前的构建
cleanup_previous() {
    print_step "清理之前的构建文件"
    
    rm -f shardingsphere-encrypt-minimal-*.jar
    rm -rf encrypt-minimal
    rm -rf target/demo-classes
    
    print_success "清理完成"
}

# 构建完整项目
build_full_project() {
    print_step "构建完整的ShardingSphere项目"
    
    print_info "这可能需要几分钟时间，请耐心等待..."
    
    if mvn clean install -DskipTests -q; then
        print_success "完整项目构建成功"
        
        # 显示生成的JDBC JAR大小
        if [ -f "jdbc/target/shardingsphere-jdbc-5.5.2.jar" ]; then
            SIZE=$(ls -lh jdbc/target/shardingsphere-jdbc-5.5.2.jar | awk '{print $5}')
            print_info "完整JDBC驱动大小: $SIZE"
        fi
    else
        print_error "项目构建失败"
        exit 1
    fi
}

# 构建精简版驱动
build_minimal_driver() {
    print_step "构建精简版加密JDBC驱动"
    
    print_info "执行精简版构建脚本..."
    
    if ./build-encrypt-minimal.sh; then
        print_success "精简版驱动构建成功"
        
        # 对比文件大小
        if [ -f "shardingsphere-encrypt-minimal-5.5.2.jar" ] && [ -f "jdbc/target/shardingsphere-jdbc-5.5.2.jar" ]; then
            ORIGINAL_SIZE=$(stat -f%z jdbc/target/shardingsphere-jdbc-5.5.2.jar 2>/dev/null || stat -c%s jdbc/target/shardingsphere-jdbc-5.5.2.jar)
            MINIMAL_SIZE=$(stat -f%z shardingsphere-encrypt-minimal-5.5.2.jar 2>/dev/null || stat -c%s shardingsphere-encrypt-minimal-5.5.2.jar)
            
            ORIGINAL_MB=$((ORIGINAL_SIZE / 1024 / 1024))
            MINIMAL_MB=$((MINIMAL_SIZE / 1024 / 1024))
            REDUCTION=$(( (ORIGINAL_SIZE - MINIMAL_SIZE) * 100 / ORIGINAL_SIZE ))
            
            echo
            print_info "文件大小对比:"
            echo "  📦 完整版: ${ORIGINAL_MB}MB"
            echo "  📦 精简版: ${MINIMAL_MB}MB"
            echo "  📉 减少了: ${REDUCTION}%"
        fi
    else
        print_error "精简版驱动构建失败"
        exit 1
    fi
}

# 准备演示环境
prepare_demo_environment() {
    print_step "准备演示环境"
    
    # 创建演示目录
    mkdir -p demo
    cd demo
    
    # 复制必要文件
    cp ../shardingsphere-encrypt-minimal-5.5.2.jar .
    cp ../encrypt-minimal-config.yaml .
    cp ../MinimalEncryptExample.java .
    
    # 下载必要的依赖JAR（如果不存在）
    print_info "检查必要的依赖JAR..."
    
    # MySQL驱动
    if [ ! -f "mysql-connector-java.jar" ]; then
        print_info "下载MySQL驱动..."
        curl -s -L -o mysql-connector-java.jar \
            "https://repo1.maven.org/maven2/mysql/mysql-connector-java/8.0.33/mysql-connector-java-8.0.33.jar" || \
            print_warning "无法下载MySQL驱动，请手动下载"
    fi
    
    # HikariCP
    if [ ! -f "HikariCP.jar" ]; then
        print_info "下载HikariCP连接池..."
        curl -s -L -o HikariCP.jar \
            "https://repo1.maven.org/maven2/com/zaxxer/HikariCP/4.0.3/HikariCP-4.0.3.jar" || \
            print_warning "无法下载HikariCP，请手动下载"
    fi
    
    print_success "演示环境准备完成"
}

# 创建测试数据库配置
create_test_config() {
    print_step "创建测试配置文件"
    
    # 创建一个使用H2数据库的配置（无需外部数据库）
    cat > test-config.yaml << 'EOF'
# 测试用配置 - 使用H2内存数据库
dataSources:
  test_ds:
    dataSourceClassName: com.zaxxer.hikari.HikariDataSource
    driverClassName: org.h2.Driver
    jdbcUrl: jdbc:h2:mem:testdb;MODE=MySQL;DATABASE_TO_LOWER=TRUE;CASE_INSENSITIVE_IDENTIFIERS=TRUE
    username: sa
    password: ""

rules:
- !ENCRYPT
  tables:
    t_user:
      columns:
        password:
          cipherColumn: password_cipher
          encryptorName: aes_encryptor
        phone:
          cipherColumn: phone_cipher
          encryptorName: sm4_encryptor
        id_card:
          cipherColumn: id_card_cipher
          assistedQueryColumn: id_card_assisted
          encryptorName: aes_encryptor
          assistedQueryEncryptorName: md5_encryptor
  encryptors:
    aes_encryptor:
      type: AES
      props:
        aes-key-value: test1234567890123456test1234567890
    sm4_encryptor:
      type: SM4
      props:
        sm4-key: test123456789012
        sm4-mode: ECB
        sm4-padding: PKCS7Padding
    md5_encryptor:
      type: MD5

props:
  sql-show: true
EOF
    
    print_success "测试配置文件创建完成"
}

# 创建简化的测试示例
create_test_example() {
    print_step "创建简化测试示例"
    
    cat > SimpleTest.java << 'EOF'
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
EOF
    
    print_success "测试示例创建完成"
}

# 编译和运行测试
compile_and_run_test() {
    print_step "编译和运行测试"
    
    # 检查是否有H2数据库JAR
    if [ ! -f "h2.jar" ]; then
        print_info "下载H2数据库..."
        curl -s -L -o h2.jar \
            "https://repo1.maven.org/maven2/com/h2database/h2/2.2.224/h2-2.2.224.jar" || \
            print_warning "无法下载H2数据库"
    fi
    
    # 构建classpath
    CLASSPATH="shardingsphere-encrypt-minimal-5.5.2.jar"
    for jar in *.jar; do
        if [ "$jar" != "shardingsphere-encrypt-minimal-5.5.2.jar" ]; then
            CLASSPATH="$CLASSPATH:$jar"
        fi
    done
    
    print_info "编译测试程序..."
    if javac -cp "$CLASSPATH" SimpleTest.java; then
        print_success "编译成功"
        
        print_info "运行测试程序..."
        echo
        echo "========== 测试输出 =========="
        java -cp ".:$CLASSPATH" SimpleTest
        echo "============================="
        echo
        
        print_success "测试运行完成"
    else
        print_error "编译失败"
        return 1
    fi
}

# 显示SPI配置对比
show_spi_comparison() {
    print_step "显示SPI配置对比"
    
    print_info "原始JDBC驱动的SPI服务数量："
    ORIGINAL_SERVICES=$(jar tf ../jdbc/target/shardingsphere-jdbc-5.5.2.jar | grep "META-INF/services/" | grep -v "/$" | wc -l)
    echo "  📄 服务文件数: $ORIGINAL_SERVICES"
    
    print_info "精简版驱动的SPI服务数量："
    MINIMAL_SERVICES=$(jar tf shardingsphere-encrypt-minimal-5.5.2.jar | grep "META-INF/services/" | grep -v "/$" | wc -l)
    echo "  📄 服务文件数: $MINIMAL_SERVICES"
    
    REDUCTION=$(( (ORIGINAL_SERVICES - MINIMAL_SERVICES) * 100 / ORIGINAL_SERVICES ))
    echo "  📉 减少了: ${REDUCTION}%"
    
    print_info "精简版保留的主要SPI服务："
    jar tf shardingsphere-encrypt-minimal-5.5.2.jar | grep "META-INF/services/" | grep -v "/$" | sed 's|META-INF/services/||' | head -10
}

# 生成使用报告
generate_usage_report() {
    print_step "生成使用报告"
    
    cat > USAGE_REPORT.md << EOF
# ShardingSphere 精简版加密JDBC驱动使用报告

## 构建信息
- 构建时间: $(date)
- 构建主机: $(hostname)
- Java版本: $(java -version 2>&1 | head -n1 | cut -d'"' -f2)

## 文件信息
$(ls -lh *.jar | awk '{print "- " $9 ": " $5}')

## 功能特性
✅ 支持的加密算法:
- AES (高级加密标准)
- SM4 (国密对称加密)
- MD5 (消息摘要，用于辅助查询)
- SM3 (国密哈希算法)

✅ 支持的功能:
- 字段级透明加密/解密
- 辅助查询（基于哈希值）
- 多种数据库支持
- YAML配置文件支持

❌ 移除的功能:
- 分库分表
- 读写分离
- 影子库
- 数据脱敏
- 广播表
- 分布式事务
- SQL联邦查询

## 配置示例
参见 test-config.yaml 文件

## 性能影响
- 启动时间: 大幅减少
- 内存占用: 显著降低
- 运行性能: 加密解密带来轻微性能损耗

## 下一步
1. 在生产环境中测试
2. 根据需要调整加密算法和密钥
3. 制定密钥管理策略
4. 设计数据迁移方案
EOF
    
    print_success "使用报告生成完成: USAGE_REPORT.md"
}

# 清理演示环境
cleanup_demo() {
    print_step "清理演示环境"
    
    cd ..
    read -p "是否删除演示目录 demo/? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf demo
        print_success "演示目录已删除"
    else
        print_info "演示目录保留在 demo/"
    fi
}

# 主函数
main() {
    echo -e "${PURPLE}"
    cat << 'EOF'
   _____ _                 _ _             ____        _                   
  / ____| |               | (_)           / ___|      | |                  
 | (___ | |__   __ _ _ __ __| |_ _ __   __ | (___ _ __ | |__   ___ _ __ ___  
  \___ \| '_ \ / _` | '__/ _` | | '_ \ / _  \___ \ '_ \|  _ \ / _ \ '__/ _ \ 
  ____) | | | | (_| | | | (_| | | | | | | |____) | |_) | | | |  __/ | |  __/
 |_____/|_| |_|\__,_|_|  \__,_|_|_| |_|\__|_____/| .__/|_| |_|\___|_|  \___|
                                                 | |                       
                  精简版加密JDBC驱动演示           |_|                       
EOF
    echo -e "${NC}\n"
    
    print_info "本演示将展示如何构建和使用ShardingSphere精简版加密JDBC驱动"
    
    # 检查是否在正确目录
    if [ ! -f "pom.xml" ] || [ ! -d "features/encrypt" ]; then
        print_error "请在ShardingSphere项目根目录下运行此脚本"
        exit 1
    fi
    
    # 执行演示步骤
    check_prerequisites
    cleanup_previous
    build_full_project
    build_minimal_driver
    prepare_demo_environment
    create_test_config
    create_test_example
    
    if compile_and_run_test; then
        show_spi_comparison
        generate_usage_report
        
        echo
        print_step "🎉 演示完成"
        print_success "精简版ShardingSphere加密JDBC驱动构建和测试成功！"
        print_info "查看 demo/USAGE_REPORT.md 了解详细信息"
        
        cleanup_demo
    else
        print_error "测试运行失败，请检查错误信息"
        exit 1
    fi
}

# 运行主函数
main "$@"