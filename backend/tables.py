from database import get_db_connection


def create_tables():

    db = get_db_connection()

    if db is None:
        print("Database connection failed!")
        return

    cursor = db.cursor()

    # Devices table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id INT AUTO_INCREMENT PRIMARY KEY,
            ip_address VARCHAR(45) UNIQUE,
            mac_address VARCHAR(50),
            first_seen DATETIME,
            last_seen DATETIME,
            packet_count BIGINT DEFAULT 0,
            total_bytes BIGINT DEFAULT 0
        )
    """)

    # Security alerts table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_alerts (
            id INT AUTO_INCREMENT PRIMARY KEY,
            alert_type VARCHAR(100),
            source_ip VARCHAR(45),
            destination_ip VARCHAR(45),
            severity VARCHAR(30),
            description TEXT,
            timestamp DATETIME
        )
    """)

    # Traffic statistics table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS traffic_statistics (
            id INT AUTO_INCREMENT PRIMARY KEY,
            total_packets BIGINT,
            total_bytes BIGINT,
            protocol_statistics JSON,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Network connections table (includes unique_network_flow constraint)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS network_connections (
            id INT AUTO_INCREMENT PRIMARY KEY,
            source_ip VARCHAR(45),
            destination_ip VARCHAR(45),
            source_port INT,
            destination_port INT,
            protocol VARCHAR(20),
            first_seen DATETIME,
            last_seen DATETIME,
            packet_count BIGINT,
            total_bytes BIGINT,
            UNIQUE KEY unique_network_flow (
                source_ip,
                destination_ip,
                source_port,
                destination_port,
                protocol
            )
        )
    """)

    # Incident status table (non-destructive extension for incident management)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incident_status (
            alert_id INT PRIMARY KEY,
            status VARCHAR(30) NOT NULL DEFAULT 'NEW',
            notes TEXT,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        )
    """)

    # DNS records table (non-destructive extension for domain correlation)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS dns_records (
            id INT AUTO_INCREMENT PRIMARY KEY,
            domain VARCHAR(255) NOT NULL,
            querying_ip VARCHAR(45),
            resolved_ip VARCHAR(45),
            first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            query_count BIGINT DEFAULT 1,
            UNIQUE KEY uq_domain_query (domain, querying_ip)
        )
    """)

    db.commit()

    print("All NetSentry database tables created successfully!")

    cursor.close()
    db.close()


if __name__ == "__main__":
    create_tables()
