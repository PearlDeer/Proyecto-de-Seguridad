# Manual de Usuario - IDS Institucional

Este manual explica como usar el IDS Institucional desde la interfaz grafica. Esta pensado para una demostracion presencial, operacion basica en Debian Linux y administracion de los modulos principales sin tocar codigo.

## 1. Inicio rapido

### Abrir la aplicacion sin captura real

Use este modo para revisar la interfaz, usar el modo demo o configurar el sistema:

```bash
cd ids-institucional
python main.py
```

### Abrir con captura real de red

Use este modo para que Scapy pueda capturar paquetes reales:

```bash
cd ids-institucional
sudo venv/bin/python main.py
```

Si aparecen mensajes de DBus/GNOME en terminal al usar `sudo`, no son errores del IDS. Son avisos graficos de Qt bajo privilegios elevados.

## 2. Conceptos basicos

| Concepto | Significado |
| --- | --- |
| IDS | Sistema de deteccion de intrusos. Observa actividad y genera alertas. |
| Whitelist | Lista de equipos autorizados por IP y MAC. |
| DNS | Servicio que traduce dominios a IPs. Permite observar dominios consultados. |
| Blacklist | Lista local de IPs peligrosas. |
| Alerta | Evento de seguridad guardado en CSV y mostrado en interfaz. |
| WHOIS | Consulta publica para obtener datos de una IP o red. |
| Abuse Contact | Correo/contacto para reportar actividad maliciosa. |
| `.env` | Archivo local de credenciales SMTP y variables sensibles. |

## 3. Flujo general de uso

```text
1. Configurar interfaz y correo
        |
        v
2. Registrar equipos autorizados en Lista Blanca
        |
        v
3. Cargar IPs peligrosas en Threat Intelligence
        |
        v
4. Iniciar monitoreo DNS/Sitios
        |
        v
5. Revisar Dashboard y Alertas
        |
        v
6. Consultar WHOIS/Abuse si hay IP peligrosa
        |
        v
7. Marcar alertas como revisadas y conservar CSV
```

## 4. Dashboard

### Proposito

El Dashboard muestra una vista general del estado operativo del IDS. Sirve para presentar rapidamente si el monitoreo esta activo, cuantos dominios se han registrado, cuantas alertas existen y cual fue el ultimo evento importante.

### Elementos visibles

| Elemento | Que muestra |
| --- | --- |
| Estado general del IDS | Activo, detenido o error. |
| Interfaz de red activa | Interfaz seleccionada para captura. |
| Equipos autorizados | Total de registros en whitelist. |
| Eventos DNS registrados | Total de dominios en `traffic_log.csv`. |
| Alertas totales | Total de eventos en `alerts_log.csv`. |
| Alertas criticas | Alertas `CRITICAL` y `EMERGENCY`. |
| IPs peligrosas cargadas | Total de indicadores en blacklist. |
| Eventos por minuto | Actividad reciente en ventana de 60 segundos. |
| Ultimo dominio detectado | Dominio DNS mas reciente. |
| Ultima alerta | Riesgo mas reciente. |
| Ultimo evento forense | Ultima IP consultada por WHOIS. |
| Timeline | Eventos recientes DNS, alertas y WHOIS. |

### Como usarlo

1. Abra la pestana `Dashboard`.
2. Verifique el estado superior.
3. Revise tarjetas y timeline.
4. Si algo no actualiza, cambie de pestana y vuelva o use botones de recarga en las pestanas especificas.

## 5. Lista Blanca

### Proposito

La Lista Blanca define que equipos son reconocidos como autorizados. El IDS usa IP y MAC para decidir si un paquete viene de un equipo conocido o de un dispositivo sospechoso.

### Campos

| Campo | Descripcion | Ejemplo |
| --- | --- | --- |
| Nombre del equipo | Nombre claro del activo. | Equipo Administracion |
| Direccion IP | IP del equipo autorizado. | 192.168.1.25 |
| Direccion MAC | MAC de la interfaz. | AA:BB:CC:DD:EE:01 |
| Descripcion | Area, responsable o proposito. | Estacion administrativa |

### Botones

| Boton | Que hace |
| --- | --- |
| Agregar equipo | Guarda un nuevo equipo en `data/whitelist.json`. |
| Editar seleccionado | Actualiza el equipo elegido en la tabla. |
| Eliminar seleccionado | Elimina el equipo elegido. |
| Limpiar formulario | Borra campos y seleccion. |
| Recargar lista | Lee nuevamente `whitelist.json`. |

### Como agregar un equipo

1. Abra `Lista Blanca`.
2. Complete nombre, IP, MAC y descripcion.
3. Presione `Agregar equipo`.
4. Revise que aparezca en la tabla.
5. El cambio queda guardado en `data/whitelist.json`.

### Que pasa si cambia algo

| Cambio | Efecto |
| --- | --- |
| Agregar equipo | El IDS lo tratara como autorizado si IP y MAC coinciden. |
| Editar IP | Se actualiza el criterio de autorizacion. |
| Editar MAC | Se actualiza el criterio de Capa 2. |
| Eliminar equipo | El trafico de ese equipo puede generar alertas. |

### Reglas de autorizacion

| Resultado | Significado |
| --- | --- |
| `AUTHORIZED` | IP y MAC coinciden con el mismo registro. |
| `UNKNOWN_DEVICE` | No existe IP ni MAC. |
| `UNKNOWN_IP` | La MAC existe, pero usa otra IP. |
| `UNKNOWN_MAC` | La IP existe, pero la MAC no coincide. |

## 6. Trafico DNS/Sitios

### Proposito

Esta pestana muestra dominios consultados en tiempo real. Permite iniciar y detener el monitoreo, elegir interfaz, recargar CSV, limpiar la vista y generar eventos de prueba.

### Controles

| Control | Funcion |
| --- | --- |
| Interfaz | Selecciona tarjeta de red, por ejemplo `wlp0s20f3`, `eth0`, `enp0s3`. |
| Iniciar monitoreo | Arranca Scapy en un hilo separado. |
| Detener monitoreo | Detiene la captura. |
| Recargar CSV | Lee `logs/traffic_log.csv`. |
| Limpiar vista | Limpia la tabla visible, no borra el CSV. |
| Generar evento de prueba | Inserta un DNS falso en tabla y CSV. |

### Tabla

| Columna | Significado |
| --- | --- |
| Hora | Hora del evento DNS. |
| IP origen | Equipo que hizo la consulta. |
| MAC origen | MAC detectada si esta disponible. |
| Dominio | Dominio consultado. |
| Protocolo | Normalmente `DNS`. |
| Evento | Tipo de evento, por ejemplo `DNS_QUERY`. |

### Monitoreo real

Para capturar trafico real:

```bash
sudo venv/bin/python main.py
```

Luego:

1. Abra `Trafico DNS/Sitios`.
2. Seleccione interfaz correcta.
3. Presione `Iniciar monitoreo`.
4. Navegue o genere trafico DNS en la red.
5. Revise tabla y Dashboard.

### Modo demo

Si no hay trafico real, presione `Generar evento de prueba`. Esto guarda:

| Campo | Valor demo |
| --- | --- |
| IP origen | 192.168.1.50 |
| MAC origen | AA:BB:CC:DD:EE:FF |
| Dominio | ejemplo-institucional.local |
| Protocolo | DNS |
| Evento | DNS_QUERY |

## 7. Alertas

### Proposito

La pestana Alertas centraliza eventos de seguridad. Muestra severidad, origen, destino, riesgo, estado y detalle forense cuando aplica.

### Tarjetas superiores

| Tarjeta | Muestra |
| --- | --- |
| Total de alertas | Total en `alerts_log.csv`. |
| Criticas | Total `CRITICAL`. |
| Emergencias | Total `EMERGENCY`. |
| Ultima alerta | Riesgo mas reciente. |

### Botones

| Boton | Funcion |
| --- | --- |
| Recargar alertas | Lee `alerts_log.csv`. |
| Limpiar vista | Limpia la tabla visible, no borra CSV. |
| Marcar como revisada | Cambia estado de la alerta seleccionada. |
| Consultar WHOIS nuevamente | Ejecuta WHOIS sobre la IP destino seleccionada. |
| Generar alerta equipo no autorizado | Crea alerta demo `CRITICAL`. |
| Generar alerta IP peligrosa | Crea alerta demo `EMERGENCY` y consulta WHOIS. |

### Severidades

| Severidad | Interpretacion |
| --- | --- |
| `INFO` | Informativo o prueba. |
| `WARNING` | Anomalia moderada. |
| `CRITICAL` | Riesgo importante, por ejemplo equipo no autorizado. |
| `EMERGENCY` | Riesgo maximo, por ejemplo IP peligrosa. |

### Detalle de alerta

Al seleccionar una alerta se muestra:

- Informacion general.
- IP y MAC origen.
- IP destino.
- Severidad.
- Estado.
- WHOIS/Abuse si existe.
- Recomendacion operativa.

### Como revisar una alerta

1. Seleccione una fila.
2. Lea el panel de detalle.
3. Si hay IP destino, presione `Consultar WHOIS nuevamente`.
4. Tome accion operativa.
5. Presione `Marcar como revisada`.

## 8. Threat Intelligence Local

### Proposito

Administra una blacklist local de IPs peligrosas. Si el IDS ve trafico hacia una IP de esta lista, genera alerta `EMERGENCY`.

### Campos

| Campo | Uso |
| --- | --- |
| IP | IP peligrosa externa. |
| Tipo de riesgo | Botnet, Malware, Scanner, TOR, etc. |
| Severidad | EMERGENCY, CRITICAL, WARNING o INFO. |
| Fuente | Origen del indicador. |
| Descripcion | Contexto del riesgo. |

### Botones

| Boton | Funcion |
| --- | --- |
| Agregar IP | Agrega indicador a `blacklist_ips.json`. |
| Editar seleccionada | Actualiza indicador elegido. |
| Eliminar seleccionada | Borra indicador elegido. |
| Probar IP | Busca una IP en la blacklist local. |
| Consultar WHOIS de IP seleccionada | Ejecuta WHOIS y muestra resultado. |
| Generar alerta de prueba con esta IP | Crea alerta EMERGENCY con la IP seleccionada. |
| Recargar blacklist | Lee de nuevo el JSON. |

### Como agregar una IP peligrosa

1. Abra `Threat Intelligence`.
2. Complete IP, riesgo, severidad, fuente y descripcion.
3. Presione `Agregar IP`.
4. Verifique que aparezca en la tabla.

### Como probar una IP

1. Seleccione o escriba una IP.
2. Presione `Probar IP`.
3. El sistema indica si aparece en la blacklist local.

### Como consultar WHOIS

1. Seleccione una IP.
2. Presione `Consultar WHOIS de IP seleccionada`.
3. Revise el panel `Resultado WHOIS`.
4. El resultado se guarda en `logs/forensic_log.csv`.

## 9. Configuracion

### Proposito

Esta pestana centraliza parametros de operacion: interfaz de red, cooldown, correo administrador, SMTP y creacion de `.env`.

### Secciones

| Seccion | Contenido |
| --- | --- |
| Correo del administrador | ADMIN_EMAIL destino de alertas. |
| Captura de red | Interfaz activa y cooldown. |
| Servidor SMTP | Host, puerto, STARTTLS, usuario, password y remitente. |
| Variables de entorno y ejecucion | Estado de `.env` y comando recomendado. |

### Configurar correo SMTP

1. Abra `Configuracion`.
2. Si no existe `.env`, presione `Crear .env desde plantilla`.
3. Escriba el correo administrador.
4. Active `Enviar correos reales si .env esta completo` solo cuando tenga credenciales listas.
5. Configure:
   - `SMTP_HOST`
   - `SMTP_PORT`
   - `SMTP_USER`
   - `SMTP_PASSWORD`
   - `SMTP_FROM`
   - `SMTP_STARTTLS`
6. Presione `Guardar configuracion`.
7. Presione `Probar correo`.

### Configuracion Gmail recomendada

| Variable | Valor tipico |
| --- | --- |
| SMTP_ENABLED | true |
| SMTP_HOST | smtp.gmail.com |
| SMTP_PORT | 587 |
| SMTP_STARTTLS | true |
| SMTP_USER | correo_admin@gmail.com |
| SMTP_PASSWORD | Contrasena de aplicacion |
| SMTP_FROM | ids@institucion.mx |
| ADMIN_EMAIL | administrador@institucion.mx |

Gmail requiere una contrasena de aplicacion, no la contrasena normal de la cuenta.

### Modo simulado

Si `SMTP_ENABLED=false`, el IDS no envia correo real. Aun asi:

- Genera alerta.
- Guarda CSV.
- Actualiza Dashboard.
- Marca estado como `Correo: Simulado`.

### Cooldown

El cooldown evita muchas alertas/correos repetidos del mismo tipo en poco tiempo.

| Valor | Efecto |
| --- | --- |
| 0 | Sin espera. Util solo para pruebas controladas. |
| 300 | Recomendado: 5 minutos. |
| 600 o mas | Reduce ruido en redes con mucho trafico. |

## 10. Correo de alertas

### Cuando se envia

El correo se intenta enviar si:

1. SMTP esta habilitado.
2. `.env` contiene valores completos.
3. No aplica cooldown.
4. El proveedor SMTP acepta conexion y autenticacion.

### Correo por equipo no autorizado

Incluye:

- Fecha y hora.
- IP origen.
- MAC origen.
- Motivo.
- Severidad.
- Mensaje.
- Recomendacion de verificar si pertenece a la organizacion.

### Correo por IP peligrosa

Incluye:

- Encabezado de emergencia.
- IP/MAC origen.
- IP destino peligrosa.
- Tipo de riesgo.
- Severidad.
- Fuente y descripcion.
- ASN, pais, proveedor y abuse contact si WHOIS lo entrega.
- Recomendacion de bloqueo y revision.

## 11. Archivos generados

| Archivo | Cuando cambia |
| --- | --- |
| `data/whitelist.json` | Al agregar, editar o eliminar equipos. |
| `data/blacklist_ips.json` | Al administrar IPs peligrosas. |
| `data/settings.json` | Al guardar configuracion no sensible. |
| `.env` | Al crear o guardar variables sensibles desde Configuracion. |
| `logs/traffic_log.csv` | Al detectar DNS o generar evento demo. |
| `logs/alerts_log.csv` | Al generar alertas reales o demo. |
| `logs/forensic_log.csv` | Al consultar WHOIS. |
| `logs/system_events.csv` | Al registrar cambios administrativos o errores relevantes. |

## 12. Diagramas operativos

### Alerta por equipo no autorizado

```text
Paquete de red
   |
   v
IP/MAC origen
   |
   v
Whitelist
   |
   +-- Coincide -> sin alerta
   |
   +-- No coincide -> alerta CRITICAL
                     |
                     v
                 alerts_log.csv
                     |
                     v
                 Alertas + Dashboard
```

### Alerta por IP peligrosa

```text
Paquete con destino externo
   |
   v
Blacklist local
   |
   +-- No aparece -> sin alerta
   |
   +-- Aparece -> EMERGENCY
                  |
                  v
              WHOIS/Abuse
                  |
                  v
         alerts_log.csv + forensic_log.csv
                  |
                  v
         Correo real o simulado + Dashboard
```

### Correo SMTP

```text
Alerta generada
   |
   v
SMTP_ENABLED?
   |
   +-- false -> Correo: Simulado
   |
   +-- true -> Leer .env -> STARTTLS -> login -> enviar
```

## 13. Recomendaciones para presentacion presencial

1. Abra con `python main.py` para mostrar interfaz sin permisos.
2. Explique Dashboard.
3. Muestre Lista Blanca.
4. Use `Generar evento de prueba` en Trafico DNS/Sitios.
5. Use `Generar alerta equipo no autorizado`.
6. Use `Generar alerta IP peligrosa`.
7. Muestre WHOIS en Alertas o Threat Intelligence.
8. Muestre CSV en `logs/`.
9. Muestre `.env.example`, no `.env`.
10. Si quiere captura real, cierre y abra con `sudo venv/bin/python main.py`.

## 14. Solucion de problemas

| Problema | Que revisar |
| --- | --- |
| La app no abre | Ejecutar desde carpeta `ids-institucional`; revisar PyQt6 en venv. |
| Scapy no captura | Ejecutar con `sudo venv/bin/python main.py`. |
| Dice Scapy no instalado | Usar `venv/bin/python`; no instalar `scrapy`. |
| No aparecen DNS | Revisar interfaz, DoH, cache DNS o trafico insuficiente. |
| Muchas alertas | Aumentar cooldown y completar whitelist. |
| WHOIS falla | Instalar `whois` y revisar conexion. |
| Correo no llega | Revisar SMTP, spam, credenciales y STARTTLS. |
| JSON corrupto | La app genera `.bak` y repara estructura. |
| CSV no se actualiza | Revisar permisos de escritura en `logs/`. |

## 15. Buenas practicas

- Usar nombres claros para equipos autorizados.
- Mantener whitelist actualizada.
- Agregar a blacklist solo IPs justificadas.
- No monitorear redes ajenas.
- No publicar `.env`.
- Revisar logs despues de cada demo.
- Configurar cooldown antes de captura real.
- Explicar que DNS no muestra URL completa HTTPS.
