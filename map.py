import folium
from etl import get_db_connection
import geoip2.database
import os
from pays import get_country_name



def get_country_center_coordinates(country_code):
    # Dictionnaire des coordonnées du centre des pays
    country_coordinates = {
        "AF": (33.93911, 67.709953),  # Afghanistan
        "AL": (41.153332, 20.168331),  # Albanie
        "DZ": (28.033886, 1.659626),   # Algérie
        "AS": (-14.333333, -170.0),    # Samoa américaines
        "AD": (42.5, 1.416667),        # Andorre
        "AO": (-11.202702, 17.875),    # Angola
        "AI": (18.25, -63.166667),     # Anguilla
        "AQ": (-90.0, 0.0),            # Antarctique
        "AG": (17.05, -61.783333),     # Antigua-et-Barbuda
        "AR": (-38.4161, -63.616667),  # Argentine
        "AM": (40.0, 45.0),            # Arménie
        "AW": (12.516667, -69.966667), # Aruba
        "AU": (-27.0, 133.0),          # Australie
        "AT": (47.333333, 13.333333),  # Autriche
        "AZ": (40.5, 47.5),            # Azerbaïdjan
        "FR": (46.603354, 1.888334),
        "US": (37.09024, -95.712891)
    }
    
    return country_coordinates.get(country_code, (None, None))


def get_coordinates(ip_address):
    try:
        reader = geoip2.database.Reader('GrpC/GeoLite2-Country.mmdb')
        response = reader.country(ip_address)

        country_code = response.country.iso_code

        country_center_coordinates = get_country_center_coordinates(country_code)

        return country_center_coordinates
    except Exception as e:
        print(f"Error occurred while retrieving coordinates: {str(e)}")
        return None, None


def plot_failed_connection_attempts_with_country(fcai_c_data):
    if fcai_c_data:
        m = folium.Map(location=[0, 0], zoom_start=2)

        for ip_address, data in fcai_c_data.items():
            lat, lon = get_coordinates(ip_address)
            if lat is not None and lon is not None:
                country_name = get_country_name(data['country'])
                popup_text = f"Country: {country_name}<br>IP Address: {ip_address}<br>Failed Attempts: {data['failed_attempts']}"
                folium.Marker(location=[lat, lon], popup=popup_text).add_to(m)

        temp_file = "fcai_c_map.html"
        m.save(temp_file)

        if os.path.exists(temp_file):
            return temp_file
        else:
            print("Erreur: Le fichier temporaire n'existe pas.")
            return None

