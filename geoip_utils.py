import geoip2.database

# Ruta a la base de datos GeoIP2
geoip_db_path = '/path/to/GeoLite2-City.mmdb'


def obtener_info_geoip(ip):
    with geoip2.database.Reader(geoip_db_path) as reader:
        try:
            response = reader.city(ip)
            return {
                'country': response.country.name,
                'city': response.city.name,
                'latitude': response.location.latitude,
                'longitude': response.location.longitude
            }
        except geoip2.errors.AddressNotFoundError:
            return {
                'country': 'Unknown',
                'city': 'Unknown',
                'latitude': 'Unknown',
                'longitude': 'Unknown'
            }
