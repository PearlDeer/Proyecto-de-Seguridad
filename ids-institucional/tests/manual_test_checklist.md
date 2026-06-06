# Pruebas Manuales - IDS Institucional

## Prueba 1

Nombre: Abrir aplicacion.

Pasos:
1. Activar entorno virtual.
2. Ejecutar `python main.py`.
3. Verificar que abre la ventana principal.

Resultado esperado: La ventana principal abre y muestra Dashboard.

Estado: Pendiente / Correcto / Error.

## Prueba 2

Nombre: Revisar Dashboard.

Pasos:
1. Abrir Dashboard.
2. Revisar tarjetas de DNS, equipos, alertas e IPs peligrosas.
3. Revisar timeline.

Resultado esperado: Las metricas cargan desde JSON/CSV sin errores.

Estado: Pendiente / Correcto / Error.

## Prueba 3

Nombre: Agregar equipo autorizado.

Pasos:
1. Abrir Lista Blanca.
2. Escribir nombre, IP valida y MAC valida.
3. Pulsar Agregar equipo.

Resultado esperado: El equipo aparece en tabla y `data/whitelist.json`.

Estado: Pendiente / Correcto / Error.

## Prueba 4

Nombre: Editar equipo autorizado.

Pasos:
1. Seleccionar un equipo.
2. Cambiar descripcion o nombre.
3. Pulsar Editar seleccionado.

Resultado esperado: La tabla y JSON reflejan el cambio.

Estado: Pendiente / Correcto / Error.

## Prueba 5

Nombre: Eliminar equipo autorizado.

Pasos:
1. Seleccionar un equipo de prueba.
2. Pulsar Eliminar seleccionado.
3. Recargar lista.

Resultado esperado: El equipo ya no aparece.

Estado: Pendiente / Correcto / Error.

## Prueba 6

Nombre: Validar IP/MAC invalidas.

Pasos:
1. Intentar agregar IP invalida.
2. Intentar agregar MAC invalida.
3. Intentar agregar nombre vacio.

Resultado esperado: La aplicacion muestra advertencia y no guarda datos.

Estado: Pendiente / Correcto / Error.

## Prueba 7

Nombre: Validar duplicados en whitelist.

Pasos:
1. Intentar registrar una IP ya existente.
2. Intentar registrar una MAC ya existente.

Resultado esperado: La aplicacion rechaza duplicados.

Estado: Pendiente / Correcto / Error.

## Prueba 8

Nombre: Generar evento DNS simulado.

Pasos:
1. Abrir Trafico DNS/Sitios.
2. Pulsar Generar evento de prueba.
3. Revisar tabla y Dashboard.

Resultado esperado: El evento aparece en GUI y `logs/traffic_log.csv`.

Estado: Pendiente / Correcto / Error.

## Prueba 9

Nombre: Iniciar monitoreo real.

Pasos:
1. Ejecutar `sudo venv/bin/python main.py`.
2. Seleccionar interfaz.
3. Pulsar Iniciar monitoreo.

Resultado esperado: Estado cambia a Monitoreando sin congelar la interfaz.

Estado: Pendiente / Correcto / Error.

## Prueba 10

Nombre: Generar trafico DNS real.

Pasos:
1. Con monitoreo activo, ejecutar `nslookup debian.org`.
2. Ejecutar `nslookup python.org`.
3. Revisar tabla.

Resultado esperado: Los dominios aparecen en Trafico DNS/Sitios y CSV.

Estado: Pendiente / Correcto / Error.

## Prueba 11

Nombre: Detener monitoreo.

Pasos:
1. Pulsar Detener monitoreo.
2. Revisar estado.

Resultado esperado: Estado cambia a Detenido.

Estado: Pendiente / Correcto / Error.

## Prueba 12

Nombre: Generar alerta de equipo no autorizado.

Pasos:
1. Abrir Alertas.
2. Pulsar Generar alerta equipo no autorizado.
3. Revisar Dashboard.

Resultado esperado: Se registra alerta en `logs/alerts_log.csv`.

Estado: Pendiente / Correcto / Error.

## Prueba 13

Nombre: Generar alerta de IP peligrosa.

Pasos:
1. Abrir Alertas.
2. Pulsar Generar alerta IP peligrosa.
3. Revisar detalle y Dashboard.

Resultado esperado: Se registra alerta `EMERGENCY` y resultado forense si WHOIS responde.

Estado: Pendiente / Correcto / Error.

## Prueba 14

Nombre: Consultar WHOIS.

Pasos:
1. Seleccionar alerta con IP destino.
2. Pulsar Consultar WHOIS nuevamente.
3. Revisar detalle.

Resultado esperado: Resultado guardado en `logs/forensic_log.csv` o error controlado.

Estado: Pendiente / Correcto / Error.

## Prueba 15

Nombre: Administrar IP peligrosa.

Pasos:
1. Abrir Threat Intelligence.
2. Agregar IP de prueba valida.
3. Editarla.
4. Eliminarla.

Resultado esperado: `data/blacklist_ips.json` cambia correctamente.

Estado: Pendiente / Correcto / Error.

## Prueba 16

Nombre: Probar IP en blacklist.

Pasos:
1. Abrir Threat Intelligence.
2. Escribir una IP existente.
3. Pulsar Probar IP.

Resultado esperado: La aplicacion informa que el indicador existe.

Estado: Pendiente / Correcto / Error.

## Prueba 17

Nombre: Validar `.env.example`.

Pasos:
1. Abrir `.env.example`.
2. Confirmar `SMTP_ENABLED=false`.
3. Confirmar correo `al281268@edu.uaa.mx`.

Resultado esperado: No hay contrasenas reales.

Estado: Pendiente / Correcto / Error.

## Prueba 18

Nombre: Probar correo simulado.

Pasos:
1. Abrir Configuracion.
2. Mantener `SMTP_ENABLED=false`.
3. Pulsar Probar correo.

Resultado esperado: Se informa modo simulado y la aplicacion no falla.

Estado: Pendiente / Correcto / Error.

## Prueba 19

Nombre: Probar correo real.

Pasos:
1. Crear `.env` con credenciales reales autorizadas.
2. Activar `SMTP_ENABLED=true`.
3. Pulsar Probar correo.

Resultado esperado: Se envia correo o se registra error SMTP controlado.

Estado: Pendiente / Correcto / Error.

## Prueba 20

Nombre: Cerrar y reabrir aplicacion.

Pasos:
1. Cerrar aplicacion.
2. Ejecutar `python main.py`.
3. Revisar persistencia de whitelist, blacklist y configuracion.

Resultado esperado: Los datos persisten.

Estado: Pendiente / Correcto / Error.
