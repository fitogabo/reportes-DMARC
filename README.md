Este script Python analiza reportes DMARC (Domain-based Message Authentication, Reporting, and Conformance) y genera un informe sobre los resultados.

Funcionalidades

1. Análisis de reportes: El script lee los reportes DMARC XML en la carpeta que se ajusta a tu ruta específica (por ejemplo, /path/to/your/reports) y los analiza utilizando bibliotecas como xml.etree.ElementTree y pandas.
2. Conversión de fechas: El script convierte las fechas en formato Unix a formato día-mes-año utilizando la función convertir_fecha.
3. Análisis de registros: El script extrae información de cada registro, como dirección IP de origen, conteo de correos, disposición (pass/fail), y autenticación DKIM/SPF.
4. Generación de informes: El script genera un informe detallado sobre los resultados SPF, incluyendo el porcentaje de correos autenticados y una lista de correos que fallaron la autenticación.
5. Guardado del informe en CSV: El script guarda el informe en un archivo CSV llamado analisis_dmarc.csv para análisis posterior.
Requisitos

1. Python 3.x
2. Bibliotecas: xml.etree.ElementTree, pandas
3. Reportes DMARC XML en la carpeta especificada

Uso
1. Clona el repositorio y descarga los reportes DMARC XML.
2. Ejecuta el script con Python (por ejemplo, python anlisis_dmarc.py).
3. Verifica el informe generado en el archivo CSV.

