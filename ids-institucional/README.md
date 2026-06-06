# IDS Institucional

IDS Institucional es una aplicacion defensiva desarrollada en Python para Debian Linux. Su objetivo es apoyar el monitoreo academico de una red autorizada mediante lista blanca IP/MAC, captura DNS con Scapy, deteccion contra una blacklist local, alertas visuales, bitacoras CSV, consultas WHOIS/Abuse y envio SMTP configurable.

El proyecto no usa SQL, SQLite ni motores de base de datos. La informacion operativa se guarda en archivos JSON y CSV para facilitar auditoria, portabilidad y revision durante la entrega.

## Objetivo general

Implementar un IDS institucional ligero, auditable y presentable que permita identificar actividad DNS, dispositivos no autorizados e intentos de comunicacion hacia IPs peligrosas, registrando evidencia y alertas para analisis posterior.

## Objetivos especificos

- Controlar equipos autorizados por direccion IP y MAC.
- Monitorear consultas DNS y dominios visitados.
- Detectar conexiones hacia IPs peligrosas cargadas en `data/blacklist_ips.json`.
- Generar alertas visuales y persistirlas en `logs/alerts_log.csv`.
- Enviar alertas por SMTP cuando el administrador lo habilite.
- Consultar WHOIS/Abuse Contact para apoyar analisis forense.
- Guardar bitacoras en CSV sin requerir base de datos.
- Incluir modo demo para presentacion presencial.

## Alcance

El sistema permite operar una lista blanca, capturar trafico DNS, registrar eventos, correlacionar IPs peligrosas, consultar WHOIS, configurar SMTP y revisar resultados desde una interfaz PyQt6. Esta pensado para practicas academicas y redes autorizadas.

No reemplaza un IDS empresarial, no inspecciona contenido HTTPS cifrado completo, no bloquea trafico automaticamente, no usa feeds comerciales en tiempo real y no administra usuarios por roles.

## Sistema recomendado

Debian Linux es el sistema recomendado por su compatibilidad con `libpcap`, Scapy, `tcpdump`, `whois`, OpenSSL y herramientas nativas de red. La captura real requiere permisos de socket crudo, por lo que puede ser necesario ejecutar la aplicacion con `sudo`.

## Tecnologias

- Python 3
- PyQt6
- Scapy
- JSON
- CSV
- python-dotenv
- smtplib
- WHOIS del sistema
- OpenSSL
- Debian Linux

## Por que no se usa SQL

El proyecto usa JSON y CSV porque la rubrica prioriza archivos auditables, portables y faciles de inspeccionar. Para listas pequenas, configuracion y bitacoras academicas, JSON/CSV reduce complejidad, evita servicios externos y permite validar datos manualmente. No se usa SQL ni SQLite.

## Arquitectura

`main.py` inicializa la aplicacion, asegura archivos base y carga la ventana principal. La logica defensiva vive en `app/core/`, la interfaz en `app/gui/` y las utilidades compartidas en `app/utils/`.

```text
ids-institucional/
  main.py
  requirements.txt
  .env.example
  data/
    whitelist.json
    blacklist_ips.json
    settings.json
  logs/
    traffic_log.csv
    alerts_log.csv
    forensic_log.csv
    system_events.csv
  app/
    core/
      packet_sniffer.py
      dns_monitor.py
      whitelist_manager.py
      threat_intel.py
      forensic_lookup.py
      alert_manager.py
      log_manager.py
    gui/
      main_window.py
      dashboard_tab.py
      whitelist_tab.py
      traffic_tab.py
      alerts_tab.py
      threat_tab.py
      settings_tab.py
      styles.py
    utils/
      validators.py
      config_loader.py
      network_utils.py
  MANUAL_USUARIO.md
  CHECKLIST_ENTREGA.md
  tests/manual_test_checklist.md
```

## Modulos principales

- `packet_sniffer.py`: ejecuta captura Scapy en un hilo separado, procesa paquetes sin congelar la GUI, detecta errores de permisos y emite eventos DNS/alertas.
- `dns_monitor.py`: extrae consultas DNS, decodifica `qname`, evita dominios vacios y genera filas compatibles con `traffic_log.csv`.
- `whitelist_manager.py`: administra equipos autorizados, valida IP/MAC, evita duplicados y evalua `is_authorized(ip, mac)`.
- `threat_intel.py`: administra `blacklist_ips.json`, valida IPs peligrosas y permite consulta local.
- `forensic_lookup.py`: ejecuta `whois`, extrae ASN, pais, proveedor y abuse contact cuando aparecen, y guarda resultados.
- `alert_manager.py`: crea alertas, aplica cooldown, registra CSV y envia correo real o simulado segun SMTP.
- `log_manager.py`: centraliza escrituras y lecturas CSV.

## Modulos GUI

- `main_window.py`: ventana principal, navegacion lateral y conexion de senales entre pestanas.
- `dashboard_tab.py`: metricas, estado del IDS, actividad reciente y timeline.
- `whitelist_tab.py`: alta, edicion, eliminacion y recarga de equipos autorizados.
- `traffic_tab.py`: seleccion de interfaz, inicio/detencion de captura, tabla DNS y evento demo.
- `alerts_tab.py`: revision de alertas, detalle, WHOIS y alertas de prueba.
- `threat_tab.py`: gestion de IPs peligrosas, prueba local, WHOIS y alerta demo.
- `settings_tab.py`: correo administrador, SMTP, cooldown, interfaz y creacion de `.env`.
- `styles.py`: estilo visual oscuro, sobrio e institucional.

## Utilidades

- `validators.py`: validacion y normalizacion de IP/MAC.
- `config_loader.py`: crea carpetas, JSON, CSV, encabezados y respaldos `.bak` si hay corrupcion.
- `network_utils.py`: hostname, IP local estimada e interfaces disponibles.

## Instalacion en Debian

```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv libpcap-dev tcpdump whois openssl -y
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python main.py
```

Para captura real:

```bash
sudo venv/bin/python main.py
```

La captura requiere permisos porque Scapy necesita acceso a paquetes de red. Para listar interfaces:

```bash
ip link show
```

Para generar trafico DNS:

```bash
nslookup debian.org
nslookup python.org
```

## Configuracion SMTP y correo institucional

El correo administrador predeterminado es `al281268@edu.uaa.mx`. Puede cambiarse en `data/settings.json`, en `.env` mediante `ADMIN_EMAIL` y desde la pestana Configuracion.

`.env.example` contiene una plantilla segura:

```env
SMTP_ENABLED=false
SMTP_HOST=smtp.office365.com
SMTP_PORT=587
SMTP_STARTTLS=true
SMTP_USER=al281268@edu.uaa.mx
SMTP_PASSWORD=colocar_password_o_app_password_aqui
SMTP_FROM=al281268@edu.uaa.mx
ADMIN_EMAIL=al281268@edu.uaa.mx
ALERT_COOLDOWN_SECONDS=300
```

`SMTP_ENABLED=false` no envia correos reales; registra el estado como simulado. `SMTP_ENABLED=true` intenta envio real usando `.env`. No subir `.env` a GitHub ni compartirlo. `.env.example` si puede versionarse porque no contiene contrasenas reales.

En Microsoft 365 institucional puede requerirse SMTP AUTH habilitado, permiso del administrador, contrasena de aplicacion si la organizacion lo permite y revision de politicas de seguridad. Si SMTP falla, el IDS sigue funcionando, guarda la alerta y registra el error en `logs/system_events.csv`. Revisar tambien spam o correo no deseado.

## Archivos JSON

`data/settings.json`:

```json
{
  "admin_email": "al281268@edu.uaa.mx",
  "capture_interface": "eth0",
  "monitoring_enabled": false,
  "dns_logging_enabled": true,
  "threat_intel_enabled": true,
  "smtp_enabled": false,
  "alert_cooldown_seconds": 300
}
```

`data/whitelist.json` guarda equipos autorizados con `id`, `device_name`, `ip`, `mac`, `description` y `created_at`.

`data/blacklist_ips.json` guarda indicadores con `ip`, `risk_type`, `severity`, `source` y `description`.

Si un JSON esta vacio se regenera con estructura minima. Si esta corrupto se crea respaldo `.bak`, se regenera el archivo y se registra evento de sistema.

## Archivos CSV

- `logs/traffic_log.csv`: `date,time,src_ip,src_mac,domain,protocol,event_type`
- `logs/alerts_log.csv`: `date,time,severity,src_ip,src_mac,dst_ip,risk_type,message,status`
- `logs/forensic_log.csv`: `date,time,ip,asn,country,abuse_contact,provider,raw_summary`
- `logs/system_events.csv`: `date,time,event_type,module,message`

Si un CSV falta o esta vacio, se crea con encabezado. Si el encabezado no coincide, se respalda y se repara sin usar SQL.

## Flujo IDS

1. `main.py` asegura carpetas `data/`, `logs/` y `assets/`.
2. Se cargan configuracion, whitelist y blacklist.
3. El usuario selecciona interfaz e inicia monitoreo.
4. Scapy captura paquetes en hilo separado.
5. `dns_monitor.py` registra consultas DNS en CSV.
6. `whitelist_manager.py` valida IP/MAC de origen.
7. `threat_intel.py` correlaciona IP destino externa contra blacklist local.
8. `alert_manager.py` crea alerta, aplica cooldown y registra CSV.
9. Para IP peligrosa se consulta WHOIS/Abuse y se guarda evidencia.
10. La GUI actualiza Dashboard, Trafico, Alertas y Threat Intelligence.

## Uso de pestanas

Dashboard muestra estado, eventos DNS, equipos autorizados, alertas, IPs peligrosas, actividad reciente y timeline.

Lista Blanca permite agregar, editar, eliminar y recargar equipos autorizados. No permite nombre vacio, IP invalida, MAC invalida ni duplicados.

Trafico DNS/Sitios permite seleccionar interfaz, iniciar/detener monitoreo, recargar CSV, limpiar vista y generar un evento DNS simulado.

Alertas permite consultar alertas, ver detalle, marcar revisada, relanzar WHOIS y generar alertas demo de equipo desconocido o IP peligrosa.

Threat Intelligence permite administrar IPs peligrosas, probar IP local, consultar WHOIS y generar alerta EMERGENCY de prueba.

Configuracion permite editar correo administrador, SMTP, STARTTLS, host, puerto, usuario, remitente, cooldown e interfaz.

## Modo demo

Para exposicion presencial se puede usar sin captura real:

1. Ejecutar `python main.py`.
2. Abrir Dashboard.
3. Agregar un equipo autorizado en Lista Blanca.
4. Ir a Trafico DNS/Sitios y pulsar Generar evento de prueba.
5. Ir a Alertas y generar alerta de equipo no autorizado.
6. Generar alerta de IP peligrosa.
7. En Threat Intelligence, consultar WHOIS o generar alerta con una IP seleccionada.
8. Mostrar `logs/traffic_log.csv`, `logs/alerts_log.csv` y `logs/forensic_log.csv`.
9. Mostrar `.env.example` con SMTP simulado.

## Checklist para presentacion

- App abre en Debian.
- Dashboard visible.
- Lista blanca agrega, edita y elimina.
- Evento DNS simulado aparece en tabla y CSV.
- Monitoreo real inicia con `sudo venv/bin/python main.py`.
- Alertas demo se guardan.
- IP peligrosa genera EMERGENCY.
- WHOIS funciona o falla controladamente.
- SMTP simulado no requiere credenciales.
- README, manual y checklists estan disponibles.

## Troubleshooting

PyQt6 no abre: activar entorno virtual e instalar dependencias.

```bash
source venv/bin/activate
pip install -r requirements.txt
python main.py
```

Scapy no captura o permiso denegado: ejecutar con permisos.

```bash
sudo venv/bin/python main.py
```

Interfaz incorrecta o no aparecen DNS: revisar `ip link show`, cambiar interfaz en Configuracion, generar trafico con `nslookup debian.org`. En VMs usar modo puente si se desea observar trafico de red. DNS over HTTPS puede ocultar consultas DNS tradicionales.

WHOIS no instalado:

```bash
sudo apt install whois
```

SMTP falla: revisar `.env`, `SMTP_ENABLED`, host, puerto, usuario, contrasena, SMTP AUTH, permisos Microsoft 365 y carpeta spam. El sistema no se cierra por error SMTP.

JSON corrupto: revisar el `.bak` generado en `data/`, corregir manualmente si se desea y reiniciar.

CSV no se actualiza: verificar permisos de escritura en `logs/`, encabezados y que la app se ejecute desde el directorio del proyecto.

No se ven alertas: confirmar que hay eventos demo o trafico hacia IP de `blacklist_ips.json`, revisar cooldown y `logs/alerts_log.csv`.

App se cierra inesperadamente: ejecutar desde terminal para ver error, luego revisar `logs/system_events.csv`.

## Limitaciones

- No sustituye un IDS empresarial.
- No analiza paquetes HTTPS cifrados completos.
- DNS over HTTPS puede ocultar dominios.
- WHOIS puede no devolver abuse contact.
- La deteccion depende de la blacklist local.
- Requiere permisos adecuados para captura real.

## Buenas practicas

- Usar solo en redes propias o autorizadas.
- Mantener whitelist y blacklist actualizadas.
- No subir `.env`.
- Proteger logs porque pueden contener datos de red.
- Revisar alertas antes de tomar decisiones.
- Documentar cambios y respaldar JSON/CSV importantes.

## Relacion con rubrica

| Criterio | Evidencia en el proyecto |
|---|---|
| Lista blanca Capa 2 y 3 | `whitelist.json`, IP/MAC, `is_authorized` |
| Monitoreo de sitios | Captura DNS y `traffic_log.csv` |
| IPs peligrosas | `blacklist_ips.json`, Threat Intelligence |
| Automatizacion forense | WHOIS/Abuse y `forensic_log.csv` |
| Proteccion de credenciales | `.env`, `.env.example`, `.gitignore` |
| Manual de usuario | `MANUAL_USUARIO.md` |
| Troubleshooting | README y manual |
| Reportes y bitacoras | CSV en `logs/` |

## Mejoras futuras

- Integracion AbuseIPDB.
- Integracion VirusTotal.
- Exportacion PDF.
- Graficas historicas.
- Integracion con firewall.
- Firma digital de logs.
- Cifrado de configuracion sensible.
- Roles de usuario.
- Instalador automatico.

## Estado final

Esta version queda preparada para pruebas en Debian, presentacion academica presencial, operacion en modo demo y configuracion SMTP real controlada por el administrador.
