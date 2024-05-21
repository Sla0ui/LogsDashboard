from etl import get_db_connection
from Dao import DataManagement as dao
import geoip2.database

class ServiceManager:

    @classmethod
    def __init__(cls, db_connection):
        cls.db_connection = db_connection
        cls.reader = geoip2.database.Reader('DATA/GeoLite2-Country.mmdb')

    @classmethod
    def get_UVPH(cls):
        query = dao.get_unique_visits_per_hour()
        with cls.db_connection.cursor(dictionary=True) as cursor:
            cursor.execute(query)
            result = cursor.fetchall()
            formatted_data = [{'hour': res['hour'], 'unique_visits': res['unique_visits']} for res in result]
        return formatted_data

    @classmethod
    def get_OAR(cls):
        query = dao.get_overall_analyzed_requests()
        with cls.db_connection.cursor() as cursor:
            cursor.execute(query)
            result = cursor.fetchone()
            if result:
                formatted_data = {
                    "Total Requests": result[0],
                    "Valid Requests": result[1],
                    "Failed Requests": result[2],
                    "Log Parsing Time": result[3],
                    "Unique Visitors": result[4],
                    "Requested Files": result[5],
                    "Excl. IP Hits": result[6],
                    "Referrers": result[7],
                    "Not Found": result[8],
                    "Static Files": result[9],
                    "Log Size": result[10],
                    "Tx. Amount": result[11]
                }
            else:
                formatted_data = {}
            return formatted_data
        
    @classmethod    
    def get_RF(cls):
        query = dao.get_resources_by_url()
        with cls.db_connection.cursor(dictionary=True) as cursor:
            cursor.execute(query)
            result = cursor.fetchall()
            formatted_data = [{'requested_url': res['requested_url'], 'count': res['count']} for res in result]
        return formatted_data

    @classmethod    
    def get_RS(cls):
        query = dao.get_static_request()
        with cls.db_connection.cursor(dictionary=True) as cursor:
            cursor.execute(query)
            results = cursor.fetchall()
            formatted_results = []
            for result in results:
                formatted_result = {
                    'static_request': result['static_request'],
                    'resource_type': result['resource_type'],
                    'request_count': result['request_count']
                }
                formatted_results.append(formatted_result)
            return formatted_results
    
    @classmethod
    def get_NFU(cls):
        query = dao.get_not_found_urls()
        with cls.db_connection.cursor(dictionary=True) as cursor:
            cursor.execute(query)
            results = cursor.fetchall()
            return [{'requested_url': result['requested_url'], 'count': result['count']} for result in results] if results else []
        
    @classmethod
    def get_VHI(cls):
        query = dao.get_visitors_hostname_ip()
        with cls.db_connection.cursor() as cursor:
            cursor.execute(query)
            results = cursor.fetchall()
            formatted_data = [{'hostname': res[0], 'ip_address': res[1], 'hits': res[2]} for res in results]
            return formatted_data

    @classmethod
    def get_FCAI(cls):
        query = dao.get_failed_connection_attempts()
        with cls.db_connection.cursor() as cursor:
            cursor.execute(query)
            results = cursor.fetchall()
            geo_data = {
                res[0]: {
                    'ip_address': res[0],
                    'failed_attempts': res[1]
                } for res in results
            }
            return geo_data

    @classmethod
    def get_FCAIC(cls):
        query = dao.get_failed_connection_attempts()
        with cls.db_connection.cursor() as cursor:
            cursor.execute(query)
            results = cursor.fetchall()
            geo_data = {}
            for ip_address, count in results:
                try:
                    country_code = cls.reader.country(ip_address).country.iso_code
                except:
                    country_code = "Unknown"
                geo_data[ip_address] = {
                    'country': country_code,
                    'failed_attempts': count
                }
            return geo_data
    
    @classmethod
    def get_HTTPSC(cls):
        query = dao.get_HTTP_status_codes()
        with cls.db_connection.cursor() as cursor:
            cursor.execute(query)
            results = cursor.fetchall()
            formatted_data = [{'status_code': res[0], 'count': res[1]} for res in results]
            return formatted_data

    @classmethod
    def get_OS(cls):
        query = dao.get_operating_systems()
        with cls.db_connection.cursor() as cursor:
            cursor.execute(query)
            results = cursor.fetchall()
            os_count = {res[0]: res[1] for res in results}
            return os_count
    
    @classmethod
    def get_BR(cls):
        query = dao.get_browsers()
        with cls.db_connection.cursor() as cursor:
            cursor.execute(query)
            results = cursor.fetchall()
            browser_count = {res[0]: res[1] for res in results}
            return browser_count

if __name__ == '__main__':
    db_connection = get_db_connection()
    service = ServiceManager(db_connection)
    #print(service.get_UVPH())
    #print(service.get_OAR())
    #print(service.get_RF()) 
    #print(service.get_RS())
    #print(service.get_NFU())
    #print(service.get_VHI())
    #print("Nombre de tentatives de connexion échouées par IP :")
    #print(service.get_FCAI())
    #print("Nombre de tentatives de connexion échouées par pays :")
    #print(service.get_FCAIC())
    #print(service.get_HTTPSC())
    #print("OPERATING SYSTEMS:")
    #print(service.get_OS())
    #print("BROWSERS:")
    #print(service.get_BR())