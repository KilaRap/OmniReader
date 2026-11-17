OMNIREADER 2.3 – Menú de funciones
DISPOSITIVO
1. Detectar lector: buscar y seleccionar el lector OMNIKEY.
2. Diagnóstico PC/SC: comprobar el servicio pcscd y la comunicación con el lector.
TARJETAS RFID
3. Consultar UID/ATR: obtener los identificadores de la tarjeta.
4. Monitor RFID: detectar inserción y retirada de tarjetas en tiempo real.
MEMORIA MIFARE
5. Lectura: leer el bloque 4 mediante una clave conocida.
6. Escritura: modificar el bloque 4 y verificar los datos escritos.
7. Comparación: comparar el contenido del bloque 4 con un HEX esperado.
UTILIDADES
8. Análisis de datos: visualizar información en HEX, ASCII, decimal y binario.
9. Conversor: convertir hexadecimal a texto y texto a hexadecimal.
10. Exportar informes: generar informes de operaciones en JSON.
11. Mapa de memoria: consultar la estructura de sectores y bloques MIFARE Classic 1K.
12. Autodiagnóstico: ejecutar pruebas internas de funcionamiento.
13. Ayuda: consultar instrucciones, instalación y limitaciones.
IDENTIFICACIÓN RFID
14. Analizador tecnológico: examinar UID y ATR para orientar la identificación de la tecnología.
15. Compatibilidad: consultar características y diferencias entre tecnologías RFID.
LABORATORIO LF / GESTIÓN
16. Registro de tarjetas: guardar tarjetas de laboratorio en JSON, con UID opcional.
17. Análisis de UID: examinar longitud, hexadecimal, decimal y binario.
18. Verificación de claves: comprobar una única clave A/B conocida en el bloque 4.
DIAGNÓSTICO Y CONTROL
19. Diagnóstico ampliado: consultar versiones, dependencias, lectores y zona horaria.
20. Resumen de sesión: visualizar lector seleccionado, última tarjeta y operaciones realizadas.

Tecnologías: Python 3 · PySCard · PC/SC · RFID LF/HF · HID OMNIKEY · MIFARE Classic 1K.

Alcance de memoria: lectura y escritura limitadas al bloque 4. Sin fuerza bruta, clonación ni modificación de tráileres de seguridad.
