def get_country_name(country_code):
    # Dictionnaire contenant les abréviations des pays et leurs noms correspondants
    country_names = {
        "AF": "Afghanistan",
        "AL": "Albanie",
        "DZ": "Algérie",
        "AD": "Andorre",
        "AO": "Angola",
        "AG": "Antigua-et-Barbuda",
        "AR": "Argentine",
        "AM": "Arménie",
        "AU": "Australie",
        "AT": "Autriche",
        "AZ": "Azerbaïdjan",
        "BS": "Bahamas",
        "BH": "Bahreïn",
        "BD": "Bangladesh",
        "BB": "Barbade",
        "BY": "Biélorussie",
        "BE": "Belgique",
        "BZ": "Belize",
        "BJ": "Bénin",
        "BT": "Bhoutan",
        "BO": "Bolivie",
        "BA": "Bosnie-Herzégovine",
        "BW": "Botswana",
        "BR": "Brésil",
        "BN": "Brunei",
        "BG": "Bulgarie",
        "BF": "Burkina Faso",
        "BI": "Burundi",
        "KH": "Cambodge",
        "CM": "Cameroun",
        "CA": "Canada",
        "CV": "Cap-Vert",
        "CF": "République centrafricaine",
        "TD": "Tchad",
        "CL": "Chili",
        "CN": "Chine",
        "CO": "Colombie",
        "KM": "Comores",
        "CD": "Congo (République démocratique)",
        "CG": "Congo (République du)",
        "CR": "Costa Rica",
        "CI": "Côte d'Ivoire",
        "HR": "Croatie",
        "CU": "Cuba",
        "CY": "Chypre",
        "CZ": "République tchèque",
        "DK": "Danemark",
        "DJ": "Djibouti",
        "DM": "Dominique",
        "DO": "République dominicaine",
        "TL": "Timor oriental",
        "EC": "Équateur",
        "EG": "Égypte",
        "SV": "Salvador",
        "GQ": "Guinée équatoriale",
        "ER": "Érythrée",
        "EE": "Estonie",
        "ET": "Éthiopie",
        "FJ": "Fidji",
        "FI": "Finlande",
        "FR": "France",
        "GA": "Gabon",
        "GM": "Gambie",
        "GE": "Géorgie",
        "DE": "Allemagne",
        "GH": "Ghana",
        "GR": "Grèce",
        "GD": "Grenade",
        "GT": "Guatemala",
        "GN": "Guinée",
        "GW": "Guinée-Bissau",
        "GY": "Guyana",
        "HT": "Haïti",
        "HN": "Honduras",
        "HU": "Hongrie",
        "IS": "Islande",
        "IN": "Inde",
        "ID": "Indonésie",
        "IR": "Iran",
        "IQ": "Irak",
        "IE": "Irlande",
        "IL": "Israël",
        "IT": "Italie",
        "JM": "Jamaïque",
        "JP": "Japon",
        "JO": "Jordanie",
        "KZ": "Kazakhstan",
        "KE": "Kenya",
        "KI": "Kiribati",
        "KP": "Corée du Nord",
        "KR": "Corée du Sud",
        "KW": "Koweït",
        "KG": "Kirghizistan",
        "LA": "Laos",
        "LV": "Lettonie",
        "LB": "Liban",
        "LS": "Lesotho",
        "LR": "Liberia",
        "LY": "Libye",
        "LI": "Liechtenstein",
        "LT": "Lituanie",
        "LU": "Luxembourg",
        "MK": "Macédoine du Nord",
        "MG": "Madagascar",
        "MW": "Malawi",
        "MY": "Malaisie",
        "MV": "Maldives",
        "ML": "Mali",
        "MT": "Malte",
        "MH": "Îles Marshall",
        "MR": "Mauritanie",
        "MU": "Maurice",
        "MX": "Mexique",
        "FM": "Micronésie",
        "MD": "Moldavie",
        "MC": "Monaco",
        "MN": "Mongolie",
        "ME": "Monténégro",
        "MA": "Maroc",
        "MZ": "Mozambique",
        "MM": "Myanmar",
        "NA": "Namibie",
        "NR": "Nauru",
        "NP": "Népal",
        "NL": "Pays-Bas",
        "NZ": "Nouvelle-Zélande",
        "NI": "Nicaragua",
        "NE": "Niger",
        "NG": "Nigéria",
        "NO": "Norvège",
        "OM": "Oman",
        "PK": "Pakistan",
        "PW": "Palau",
        "PS": "Palestine",
        "PA": "Panama",
        "PG": "Papouasie-Nouvelle-Guinée",
        "PY": "Paraguay",
        "PE": "Pérou",
        "PH": "Philippines",
        "PL": "Pologne",
        "PT": "Portugal",
        "QA": "Qatar",
        "RO": "Roumanie",
        "RU": "Russie",
        "RW": "Rwanda",
        "KN": "Saint-Kitts-et-Nevis",
        "LC": "Sainte-Lucie",
        "VC": "Saint-Vincent-et-les-Grenadines",
        "WS": "Samoa",
        "SM": "Saint-Marin",
        "ST": "Sao Tomé-et-Principe",
        "SA": "Arabie saoudite",
        "SN": "Sénégal",
        "RS": "Serbie",
        "SC": "Seychelles",
        "SL": "Sierra Leone",
                "SG": "Singapour",
        "SK": "Slovaquie",
        "SI": "Slovénie",
        "SB": "Îles Salomon",
        "SO": "Somalie",
        "ZA": "Afrique du Sud",
        "SS": "Soudan du Sud",
        "ES": "Espagne",
        "LK": "Sri Lanka",
        "SD": "Soudan",
        "SR": "Suriname",
        "SE": "Suède",
        "CH": "Suisse",
        "SY": "Syrie",
        "TJ": "Tadjikistan",
        "TZ": "Tanzanie",
        "TH": "Thaïlande",
        "TG": "Togo",
        "TO": "Tonga",
        "TT": "Trinité-et-Tobago",
        "TN": "Tunisie",
        "TR": "Turquie",
        "TM": "Turkménistan",
        "TV": "Tuvalu",
        "UG": "Ouganda",
        "UA": "Ukraine",
        "AE": "Émirats arabes unis",
        "GB": "Royaume-Uni",
        "US": "États-Unis",
        "UY": "Uruguay",
        "UZ": "Ouzbékistan",
        "VU": "Vanuatu",
        "VA": "Vatican",
        "VE": "Venezuela",
        "VN": "Vietnam",
        "YE": "Yémen",
        "ZM": "Zambie",
        "ZW": "Zimbabwe"
    }

    # Récupérer le nom du pays à partir du code de pays
    country_name = country_names.get(country_code, "Inconnu")
    return country_name

import geoip2.database

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
    
    # Récupérer les coordonnées du centre du pays à partir du dictionnaire
    return country_coordinates.get(country_code, (None, None))


def get_coordinates(ip_address):
    try:
        reader = geoip2.database.Reader('DATA/GeoLite2-Country.mmdb')
        response = reader.country(ip_address)

        country_code = response.country.iso_code

        country_center_coordinates = get_country_center_coordinates(country_code)

        return country_center_coordinates
    except Exception as e:
        print(f"Error occurred while retrieving coordinates: {str(e)}")
        return None, None