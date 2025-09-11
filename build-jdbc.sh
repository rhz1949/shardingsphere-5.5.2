#!/bin/bash

echo "Building Apache ShardingSphere JDBC Driver..."
echo "=============================================="

# Build the JDBC distribution
echo "Step 1: Building JDBC distribution with dependencies..."
mvn clean package -DskipTests -Prelease -pl distribution/jdbc -am

# Check if build was successful
if [ $? -eq 0 ]; then
    echo ""
    echo "Build completed successfully!"
    echo ""
    
    # Find and display the built JAR files
    echo "Generated JDBC distribution files:"
    find distribution/jdbc/target -name "*.tar.gz" -o -name "*.jar" | head -10
    
    echo ""
    echo "To use the JDBC driver, you can:"
    echo "1. Extract the tar.gz file and use all JARs in the lib/ directory"
    echo "2. Or use the individual JAR files from target/ directories"
    echo ""
    echo "JDBC URL format: jdbc:shardingsphere:your-config-file"
    
else
    echo "Build failed. Please check the error messages above."
    exit 1
fi