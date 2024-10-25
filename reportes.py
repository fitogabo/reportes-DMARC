import glob
import pandas as pd
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
import geoip2.database

# Ruta a la base de datos GeoIP2
geoip_db_path = '/home/gabriel/Documentos/Centro-de-Ciberseguridad/Analizador DMARC/geolite2/GeoLite2-City.mmdb'

reportes_dmarc = glob.glob(
    '/home/gabriel/Documentos/Centro-de-Ciberseguridad/gestion-dominio-gabrielpantoja/reportes/*.xml')


def convertir_fecha(fecha_unix):
    return datetime.fromtimestamp(int(fecha_unix), tz=timezone.utc).strftime('%d-%m-%Y')


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


def analizar_reportes(reportes):
    datos = []
    for reporte in reportes:
        tree = ET.parse(reporte)
        root = tree.getroot()

        # Extraer las fechas del reporte
        date_range = root.find('.//report_metadata/date_range')
        begin_date = convertir_fecha(date_range.find('begin').text)
        end_date = convertir_fecha(date_range.find('end').text)

        for record in root.findall('.//record'):
            source_ip = record.find('row/source_ip').text
            count = int(record.find('row/count').text)
            disposition = record.find('row/policy_evaluated/disposition').text
            dkim = record.find('row/policy_evaluated/dkim').text
            spf = record.find('row/policy_evaluated/spf').text

            # Obtener información geográfica
            geo_info = obtener_info_geoip(source_ip)

            datos.append({
                'source_ip': source_ip,
                'count': count,
                'disposition': disposition,
                'dkim': dkim,
                'spf': spf,
                'begin_date': begin_date,
                'end_date': end_date,
                'country': geo_info['country'],
                'city': geo_info['city'],
                'latitude': geo_info['latitude'],
                'longitude': geo_info['longitude']
            })
    return pd.DataFrame(datos)


# Analizar los reportes
df_reportes = analizar_reportes(reportes_dmarc)

# Mostrar los primeros registros para revisión
print(df_reportes.head())

# Guardar el DataFrame en un archivo CSV para análisis posterior
df_reportes.to_csv('analisis_dmarc.csv', index=False)

# Resumen de los resultados SPF
resumen_spf = df_reportes.groupby('spf').size().reset_index(name='counts')
print("\nResumen de los resultados SPF:")
print(resumen_spf)

# Porcentaje de correos autenticados por SPF
total_correos = df_reportes['count'].sum()
correos_spf_pass = df_reportes[df_reportes['spf'] == 'pass']['count'].sum()
porcentaje_spf_pass = (correos_spf_pass / total_correos) * 100
print(
    f"\nPorcentaje de correos autenticados por SPF: {porcentaje_spf_pass:.2f}%")

# Filtrar correos que fallaron la autenticación SPF
df_spf_fail = df_reportes[df_reportes['spf'] == 'fail']
print("\nCorreos que fallaron la autenticación SPF:")
print(df_spf_fail)
