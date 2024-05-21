class DataManagement:
    
    @staticmethod
    def get_unique_visits_per_hour():
        return """
            SELECT COUNT(DISTINCT ip_address) AS unique_visits,
                DATE_FORMAT(timestamp, '%Y-%m-%d %H:00:00') AS hour
            FROM access_logs,
                (SELECT MIN(timestamp) AS start_date FROM access_logs) AS start
            WHERE timestamp BETWEEN start.start_date AND DATE_ADD(start.start_date, INTERVAL 6 DAY)
            GROUP BY hour
            HAVING HOUR(hour) % 2 = 0  
            ORDER BY hour;
        """
    
    @staticmethod
    def get_overall_analyzed_requests():
        return """
        SELECT
            COUNT(*) AS "Total Requests",
            SUM(CASE WHEN status_code = 200 THEN 1 ELSE 0 END) AS "Valid Requests",
            SUM(CASE WHEN status_code != 200 THEN 1 ELSE 0 END) AS "Failed Requests",
            MAX(timestamp) - MIN(timestamp) AS "Log Parsing Time",
            COUNT(DISTINCT ip_address) AS "Unique Visitors",
            COUNT(DISTINCT requested_resource) AS "Requested Files",
            SUM(CASE WHEN status_code = 200 THEN 0 ELSE 1 END) AS "Excl. IP Hits",
            COUNT(DISTINCT user_agent) AS "Referrers",
            SUM(CASE WHEN status_code = 404 THEN 1 ELSE 0 END) AS "Not Found",
            SUM(CASE WHEN requested_resource LIKE '%.html' OR requested_resource LIKE '%.htm' OR requested_resource LIKE '%.css' OR requested_resource LIKE '%.js' THEN 1 ELSE 0 END) AS "Static Files",
            SUM(LENGTH(requested_resource)) AS "Log Size",
            SUM(LENGTH(requested_resource)) * COUNT(*) AS "Tx. Amount"
        FROM
            access_logs,
            (SELECT MIN(timestamp) AS start_date FROM access_logs) AS start
        WHERE
            timestamp BETWEEN start.start_date AND DATE_ADD(start.start_date, INTERVAL 6 DAY);
        """

    @staticmethod
    def get_resources_by_url():
        return """
        SELECT DISTINCT 
            REGEXP_SUBSTR(requested_resource, '/[a-zA-Z]+|/') AS requested_url,
            COUNT(*) AS count
        FROM access_logs,
            (SELECT MIN(timestamp) AS start_date FROM access_logs) AS start
        WHERE requested_resource IS NOT NULL
            AND timestamp BETWEEN start.start_date AND DATE_ADD(start.start_date, INTERVAL 6 DAY)
        GROUP BY requested_url
        HAVING count > 10
        ORDER BY count DESC;
        """
    
    @staticmethod
    def get_static_request():
        return """
            SELECT
                static_request,
                CASE
                    WHEN requested_resource LIKE '%.css' THEN 'CSS'
                    WHEN requested_resource LIKE '%.js' THEN 'JavaScript'
                    WHEN requested_resource LIKE '%.jpg' THEN 'JPG'
                    WHEN requested_resource LIKE '%.png' THEN 'PNG'
                    WHEN requested_resource LIKE '%.gif' THEN 'GIF'
                    ELSE 'Other'
                END AS resource_type,
                COUNT(*) AS request_count
            FROM
                access_logs,
                (SELECT MIN(timestamp) AS start_date FROM access_logs) AS start
            WHERE
                (requested_resource LIKE '%.css' 
                OR requested_resource LIKE '%.js' 
                OR requested_resource LIKE '%.jpg' 
                OR requested_resource LIKE '%.png' 
                OR requested_resource LIKE '%.gif')
                AND timestamp BETWEEN start.start_date AND DATE_ADD(start.start_date, INTERVAL 6 DAY)
            GROUP BY
                static_request,
                resource_type;
            """
    
    @staticmethod
    def get_not_found_urls():
        return """
            SELECT DISTINCT 
                REGEXP_SUBSTR(requested_resource, '^/[^/]+') AS requested_url,
                COUNT(*) AS count
            FROM access_logs,
                (SELECT MIN(timestamp) AS start_date FROM access_logs) AS start
            WHERE requested_resource IS NOT NULL
                AND timestamp BETWEEN start.start_date AND DATE_ADD(start.start_date, INTERVAL 6 DAY)
                AND status_code IN (400, 404, 500)
            GROUP BY requested_url
            HAVING count > 3
            ORDER BY count DESC;
            """
    
    @staticmethod
    def get_visitors_hostname_ip():
        return """
            SELECT DISTINCT 
            ssh.hostname AS visitor_hostname,
            REGEXP_SUBSTR(ssh.message, '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}') AS visitor_ip,
            COUNT(*) AS hits
        FROM 
            ssh_logs ssh,
            (SELECT MIN(log_date) AS start_date FROM ssh_logs) AS start
        WHERE 
            ssh.message REGEXP '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}'
            AND ssh.log_date BETWEEN start.start_date AND DATE_ADD(start.start_date, INTERVAL 6 DAY)
        GROUP BY
            visitor_hostname, visitor_ip;
        """

    @staticmethod
    def get_failed_connection_attempts():
        return """
            SELECT 
                REGEXP_SUBSTR(message, '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}') AS ip_address,
                COUNT(*) AS count
            FROM 
                ssh_logs,
                (SELECT MIN(log_date) AS start_date FROM ssh_logs) AS start
            WHERE 
                message REGEXP 'authentication failure|Failed password' 
                AND message REGEXP '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}' 
                AND log_date BETWEEN start.start_date AND DATE_ADD(start.start_date, INTERVAL 6 DAY)
            GROUP BY 
                ip_address;
        """
    
    @staticmethod
    def get_HTTP_status_codes():
        return """
            SELECT status_code, COUNT(*) AS count
            FROM access_logs,
                (SELECT MIN(timestamp) AS start_date FROM access_logs) AS start
            WHERE timestamp BETWEEN start.start_date AND DATE_ADD(start.start_date, INTERVAL 6 DAY)
            GROUP BY status_code;
            """

    @staticmethod
    def get_operating_systems():
        return """
            SELECT 
                CASE
                    WHEN user_agent REGEXP 'Windows' THEN 'Windows'
                    WHEN user_agent REGEXP 'Linux' THEN 'Linux'
                    WHEN user_agent REGEXP 'Mac' THEN 'MacOS'
                    WHEN user_agent REGEXP 'iPhone|iPad|iPod' THEN 'iOS'
                    WHEN user_agent REGEXP 'Android' THEN 'Android'
                    ELSE 'Other'
                END AS operating_system,
                COUNT(*) AS count
            FROM access_logs,
                (SELECT MIN(timestamp) AS start_date FROM access_logs) AS start
            WHERE timestamp BETWEEN start.start_date AND DATE_ADD(start.start_date, INTERVAL 6 DAY)
            GROUP BY operating_system;
        """
    
    @staticmethod
    def get_browsers():
        return """
            SELECT 
                CASE
                    WHEN user_agent REGEXP 'Chrome' THEN 'Chrome'
                    WHEN user_agent REGEXP 'Firefox' THEN 'Firefox'
                    WHEN user_agent REGEXP 'Safari' THEN 'Safari'
                    WHEN user_agent REGEXP 'Edge' THEN 'Edge'
                    WHEN user_agent REGEXP 'OPR' THEN 'Opera'
                    WHEN user_agent REGEXP 'Trident' THEN 'Internet Explorer'
                    ELSE 'Other'
                END AS browser,
                COUNT(*) AS count
            FROM access_logs,
                (SELECT MIN(timestamp) AS start_date FROM access_logs) AS start
            WHERE timestamp BETWEEN start.start_date AND DATE_ADD(start.start_date, INTERVAL 6 DAY)
            GROUP BY browser;
        """