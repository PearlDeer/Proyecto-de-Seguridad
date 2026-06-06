# IDS Institucional

IDS Institucional es una aplicacion defensiva para Debian Linux construida en Python con PyQt6, Scapy, JSON, CSV y variables de entorno `.env`. Su objetivo es monitorear trafico de red autorizado, registrar consultas DNS, validar equipos por IP/MAC, detectar destinos peligrosos mediante una blacklist local, generar alertas, consultar informacion WHOIS/Abuse y guardar evidencia operativa en archivos planos.

El proyecto no usa SQL ni SQLite. Toda la informacion operativa se guarda en JSON y CSV para mantener trazabilidad, portabilidad y revision manual sencilla.

## Documentacion

| Documento | Proposito |
| --- | --- |
| `README.md` | Documentacion tecnica completa del proyecto, arquitectura, dependencias, flujos y operacion. |
| `MANUAL_USUARIO.md` | Manual de usuario por pestanas, pasos de uso, configuracion de correo, modo demo y solucion de problemas. |
| `.env.example` | Plantilla de variables sensibles. No contiene credenciales reales. |

## Estado actual del proyecto

| Modulo | Estado | Funcion principal |
| --- | --- | --- |
| Dashboard | Implementado | Resume estado del IDS, alertas, DNS, whitelist, blacklist y eventos forenses. |
| Lista Blanca | Implementado | Administra equipos autorizados por IP/MAC en `data/whitelist.json`. |
| Trafico DNS/Sitios | Implementado | Captura paquetes con Scapy, registra dominios DNS y permite modo demo. |
| Alertas | Implementado | Genera, muestra y guarda alertas por whitelist y blacklist. |
| Threat Intelligence | Implementado | Administra IPs peligrosas locales en JSON y consulta WHOIS. |
| Configuracion | Implementado | Configura interfaz, SMTP, cooldown, `.env` y prueba de correo. |
| Automatizacion Forense | Implementado | Consulta WHOIS, extrae Abuse Contact y guarda `forensic_log.csv`. |
| SMTP seguro | Implementado | Envia o simula correos usando `.env` y cooldown. |

## Herramientas, librerias y tecnologias usadas

| Tecnologia | Uso en el proyecto | Archivo principal |
| --- | --- | --- |
| Python 3 | Lenguaje base de toda la aplicacion. | `main.py`, `app/` |
| PyQt6 | Interfaz grafica de escritorio. | `app/gui/*.py` |
| Scapy | Captura y analisis de paquetes. | `app/core/packet_sniffer.py`, `dns_monitor.py` |
| JSON | Configuracion, whitelist y blacklist. | `data/*.json` |
| CSV | Logs auditables de trafico, alertas, forense y sistema. | `logs/*.csv` |
| python-dotenv | Lectura/escritura segura de variables `.env`. | `alert_manager.py`, `settings_tab.py` |
| smtplib | Envio SMTP con STARTTLS. | `alert_manager.py` |
| subprocess | Ejecucion del comando Debian `whois`. | `forensic_lookup.py` |
| ipaddress | Validacion y normalizacion de IP. | `validators.py`, `packet_sniffer.py` |
| re | Validacion MAC y extraccion de correos WHOIS. | `validators.py`, `forensic_lookup.py` |
| whois Debian | Consulta WHOIS real de IPs peligrosas. | Sistema operativo |
| venv | Entorno aislado de dependencias Python. | `venv/` |

### Dependencias Python

El archivo `requirements.txt` contiene:

```text
PyQt6
scapy
python-dotenv
requests
python-whois
```

Notas:

- La libreria correcta de captura de paquetes es `scapy`.
- `scrapy` es otra libreria diferente, orientada a web scraping, y no sirve para este IDS.
- `python-whois` queda instalado como dependencia auxiliar, pero el flujo forense principal usa el comando Debian `whois`, que es mas confiable para IPs.

### Dependencias Debian recomendadas

```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv libpcap-dev tcpdump whois openssl
```

| Paquete | Por que se usa |
| --- | --- |
| `python3` | Ejecutar la aplicacion. |
| `python3-venv` | Crear entorno virtual local. |
| `libpcap-dev` | Soporte de captura de paquetes y filtros BPF. |
| `tcpdump` | Herramienta de diagnostico y soporte de captura en Debian. |
| `whois` | Consultas forenses WHOIS/Abuse. |
| `openssl` | Soporte general TLS/STARTTLS para SMTP. |

## Instalacion recomendada

Desde la carpeta del proyecto:

```bash
cd ids-institucional
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python main.py
```

`main.py` detecta si existe `venv/bin/python` y se relanza con ese interprete para evitar errores de dependencias instaladas en otro Python.

Para captura real de red con Scapy:

```bash
sudo venv/bin/python main.py
```

Si solo se quiere revisar la interfaz o usar modo demo, `python main.py` es suficiente. Para monitoreo real, Debian requiere permisos para sockets crudos.

## Ejecucion y permisos

| Comando | Uso recomendado |
| --- | --- |
| `python main.py` | Abrir interfaz, revisar datos, usar modo demo. |
| `venv/bin/python main.py` | Ejecutar explicitamente con el entorno virtual. |
| `sudo venv/bin/python main.py` | Captura real con Scapy en Debian. |

Al ejecutar con `sudo` pueden aparecer avisos como:

```text
qt.qpa.theme.dbus: Session DBus not running
qt.qpa.theme.gnome: dbus connection failed
```

Estos avisos son del tema grafico de Qt bajo privilegios elevados. No significan que el IDS o Scapy hayan fallado. La aplicacion usa estilo `Fusion` y reglas de logging para reducir esos mensajes.

## Estructura del proyecto

```text
ids-institucional/
├── main.py
├── requirements.txt
├── README.md
├── MANUAL_USUARIO.md
├── .env.example
├── .gitignore
├── app/
│   ├── core/
│   │   ├── packet_sniffer.py
│   │   ├── dns_monitor.py
│   │   ├── whitelist_manager.py
│   │   ├── threat_intel.py
│   │   ├── alert_manager.py
│   │   ├── forensic_lookup.py
│   │   └── log_manager.py
│   ├── gui/
│   │   ├── main_window.py
│   │   ├── dashboard_tab.py
│   │   ├── whitelist_tab.py
│   │   ├── traffic_tab.py
│   │   ├── alerts_tab.py
│   │   ├── threat_tab.py
│   │   ├── settings_tab.py
│   │   └── styles.py
│   └── utils/
│       ├── config_loader.py
│       ├── network_utils.py
│       └── validators.py
├── data/
│   ├── whitelist.json
│   ├── blacklist_ips.json
│   └── settings.json
├── logs/
│   ├── traffic_log.csv
│   ├── alerts_log.csv
│   ├── forensic_log.csv
│   └── system_events.csv
└── assets/
    └── logo_placeholder.png
```

## Arquitectura general

```text
main.py
  |
  v
MainWindow (PyQt6)
  |
  +-- DashboardTab  <--- CSV/JSON agregados
  +-- WhitelistTab  <--- WhitelistManager <--- data/whitelist.json
  +-- TrafficTab    <--- PacketSniffer + DNSMonitor
  |                       |
  |                       +-- traffic_log.csv
  |                       +-- WhitelistManager -> AlertManager
  |                       +-- ThreatIntelService -> AlertManager -> ForensicLookupService
  +-- AlertsTab     <--- AlertManager + forensic_log.csv
  +-- ThreatTab     <--- ThreatIntelService + ForensicLookupService
  +-- SettingsTab   <--- settings.json + .env
```

## Flujo completo de deteccion

```text
Paquete capturado por Scapy
        |
        v
PacketSniffer inspecciona IP/MAC y DNS
        |
        +--> Si es consulta DNS:
        |       DNSMonitor extrae dominio
        |       LogManager guarda traffic_log.csv
        |       TrafficTab y Dashboard se actualizan
        |
        +--> Si hay IP/MAC origen:
        |       WhitelistManager.is_authorized()
        |       Si no autorizado -> AlertManager -> alerts_log.csv -> Alertas/Dashboard
        |
        +--> Si destino es IP externa:
                ThreatIntelService.lookup_local()
                Si aparece en blacklist:
                    AlertManager genera EMERGENCY
                    ForensicLookupService ejecuta WHOIS
                    forensic_log.csv se actualiza
                    Correo se envia o simula
```

## Modulos core

### `packet_sniffer.py`

Responsabilidad:

- Iniciar y detener captura con Scapy.
- Ejecutar captura en hilo separado para no congelar PyQt6.
- Inspeccionar paquetes capturados.
- Enviar eventos DNS a la interfaz.
- Validar IP/MAC contra whitelist.
- Comparar IP destino externa contra blacklist.
- Generar alertas cuando corresponde.
- Manejar errores de permisos o Scapy faltante.

Detalles importantes:

- `CAPTURE_FILTER = None`: evita depender obligatoriamente de filtros BPF si `tcpdump/libpcap` no estan disponibles.
- La clasificacion DNS se hace en Python mediante `DNSMonitor`.
- La captura real requiere permisos de root o capacidades.

### `dns_monitor.py`

Responsabilidad:

- Detectar consultas DNS en paquetes Scapy.
- Extraer `qname`.
- Convertir bytes a texto.
- Evitar dominios vacios.
- Extraer fecha, hora, IP origen, MAC origen, dominio, protocolo y evento.

Evento generado:

```json
{
  "date": "YYYY-MM-DD",
  "time": "HH:MM:SS",
  "src_ip": "192.168.0.10",
  "src_mac": "AA:BB:CC:DD:EE:FF",
  "domain": "example.org",
  "protocol": "DNS",
  "event_type": "DNS_QUERY"
}
```

### `whitelist_manager.py`

Responsabilidad:

- Cargar, agregar, editar y eliminar equipos autorizados.
- Validar IP y MAC.
- Evitar duplicados.
- Registrar cambios administrativos en `system_events.csv`.
- Determinar autorizacion en tiempo real con `is_authorized(ip, mac)`.

Estados de autorizacion:

| Estado | Significado |
| --- | --- |
| `AUTHORIZED` | IP y MAC coinciden con el mismo equipo. |
| `UNKNOWN_DEVICE` | IP y MAC no aparecen en whitelist. |
| `UNKNOWN_IP` | La MAC existe, pero usa una IP no registrada. |
| `UNKNOWN_MAC` | La IP existe, pero la MAC no coincide. |

### `threat_intel.py`

Responsabilidad:

- Cargar `data/blacklist_ips.json`.
- Buscar IP destino externa en blacklist local.
- Agregar, editar y eliminar indicadores peligrosos.
- Validar IPs y campos obligatorios.
- Mantener JSON indentado y legible.

Formato de indicador:

```json
{
  "ip": "185.220.101.45",
  "risk_type": "Botnet",
  "severity": "EMERGENCY",
  "source": "Local Threat Feed",
  "description": "IP asociada a actividad maliciosa o infraestructura sospechosa"
}
```

### `alert_manager.py`

Responsabilidad:

- Crear alertas por equipo no autorizado.
- Crear alertas EMERGENCY por IP peligrosa.
- Aplicar severidades normalizadas.
- Evitar spam mediante cooldown.
- Guardar `alerts_log.csv`.
- Enviar o simular correo SMTP.
- Agregar informacion forense al correo de IP peligrosa.

Severidades:

| Severidad | Uso |
| --- | --- |
| `INFO` | Informacion o prueba. |
| `WARNING` | Anomalia moderada. |
| `CRITICAL` | Equipo no autorizado o riesgo alto. |
| `EMERGENCY` | IP peligrosa detectada en blacklist. |

### `forensic_lookup.py`

Responsabilidad:

- Ejecutar `whois <ip>` mediante `subprocess`.
- Extraer ASN, pais, proveedor y Abuse Contact cuando esten disponibles.
- Guardar resultado en `forensic_log.csv`.
- Construir resumen para interfaz y correo.
- Manejar errores sin cerrar la aplicacion.

Si no encuentra abuse contact, muestra:

```text
No se encontro contacto de abuso en la consulta WHOIS.
```

### `log_manager.py`

Responsabilidad:

- Crear CSV si no existen.
- Leer y escribir logs.
- Guardar eventos DNS, alertas, forense y sistema.
- Marcar alertas como revisadas.

### `config_loader.py`

Responsabilidad:

- Definir encabezados CSV.
- Crear estructura inicial de `data/` y `logs/`.
- Leer/escribir JSON.
- Crear backup `.bak` si un JSON esta corrupto.
- Mantener JSON indentado.

### `network_utils.py`

Responsabilidad:

- Obtener hostname.
- Obtener IP local aproximada.
- Listar interfaces de red disponibles con Scapy o `/sys/class/net`.

### `validators.py`

Responsabilidad:

- Validar IP con `ipaddress`.
- Validar MAC con expresion regular.
- Normalizar IP y MAC para comparaciones consistentes.

## Pestanas de la interfaz

| Pestana | Proposito |
| --- | --- |
| Dashboard | Vista general del estado operativo del IDS. |
| Lista Blanca | Administrar equipos autorizados por IP/MAC. |
| Trafico DNS/Sitios | Monitoreo DNS en tiempo real y modo demo. |
| Alertas | Revision de eventos de seguridad, severidad y WHOIS asociado. |
| Threat Intelligence | Gestion de IPs peligrosas locales y pruebas WHOIS. |
| Configuracion | Interfaz, SMTP, `.env`, cooldown y prueba de correo. |

## Archivos JSON

### `data/settings.json`

Guarda configuracion no sensible:

```json
{
  "admin_email": "admin@example.com",
  "capture_interface": "wlp0s20f3",
  "monitoring_enabled": false,
  "dns_logging_enabled": true,
  "threat_intel_enabled": true,
  "smtp_enabled": false,
  "alert_cooldown_seconds": 300
}
```

### `data/whitelist.json`

Guarda equipos autorizados:

```json
{
  "id": 1,
  "device_name": "Equipo Administracion",
  "ip": "192.168.1.25",
  "mac": "AA:BB:CC:DD:EE:01",
  "description": "Estacion administrativa",
  "created_at": "2026-06-05T09:05:00"
}
```

### `data/blacklist_ips.json`

Guarda IPs peligrosas:

```json
{
  "ip": "185.220.101.45",
  "risk_type": "Botnet",
  "severity": "EMERGENCY",
  "source": "Local Threat Feed",
  "description": "IP asociada a actividad maliciosa"
}
```

## Archivos CSV

| Archivo | Columnas | Uso |
| --- | --- | --- |
| `logs/traffic_log.csv` | `date,time,src_ip,src_mac,domain,protocol,event_type` | Registro DNS y sitios consultados. |
| `logs/alerts_log.csv` | `date,time,severity,src_ip,src_mac,dst_ip,risk_type,message,status` | Alertas de seguridad. |
| `logs/forensic_log.csv` | `date,time,ip,asn,country,abuse_contact,provider,raw_summary` | Resultados WHOIS/Abuse. |
| `logs/system_events.csv` | `date,time,event_type,module,message` | Cambios administrativos y errores relevantes. |

## SMTP y variables de entorno

Las credenciales no deben guardarse en codigo ni JSON. Se guardan en `.env`, que esta ignorado por `.gitignore`.

Plantilla `.env.example`:

```env
SMTP_ENABLED=false
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_STARTTLS=true
SMTP_USER=correo_admin@example.com
SMTP_PASSWORD=app_password_aqui
SMTP_FROM=ids@example.com
ADMIN_EMAIL=admin@example.com
ALERT_COOLDOWN_SECONDS=300
THREAT_INTEL_API_KEY=colocar_api_key_aqui
```

Funcionamiento:

- Si `SMTP_ENABLED=false`, el correo se simula.
- Si `SMTP_ENABLED=true`, se intenta envio real.
- `SMTP_STARTTLS=true` activa STARTTLS.
- `ALERT_COOLDOWN_SECONDS` evita correos repetidos por el mismo evento.
- La pestana Configuracion puede crear `.env` desde `.env.example`.

## Correo de alerta

### Equipo no autorizado

Incluye:

- Titulo de alerta.
- Fecha y hora.
- IP origen.
- MAC origen.
- Motivo.
- Severidad.
- Mensaje.
- Recomendacion: verificar si el equipo pertenece a la organizacion.

### IP peligrosa

Incluye:

- Encabezado `ALERTA DE EMERGENCIA - IP PELIGROSA DETECTADA`.
- Datos de red.
- Riesgo, fuente y descripcion.
- Informacion forense WHOIS.
- Abuse Contact cuando existe.
- Recomendacion de bloqueo, revision y reporte.

## Modo demo

El proyecto permite demostrar funcionamiento aunque no exista trafico real suficiente:

| Accion | Pestana | Resultado |
| --- | --- | --- |
| Generar evento DNS | Trafico DNS/Sitios | Inserta evento en tabla y `traffic_log.csv`. |
| Generar alerta equipo no autorizado | Alertas | Inserta alerta CRITICAL en `alerts_log.csv`. |
| Generar alerta IP peligrosa | Alertas | Inserta EMERGENCY, ejecuta WHOIS y guarda forense. |
| Consultar WHOIS | Threat Intelligence / Alertas | Guarda resultado en `forensic_log.csv`. |
| Probar correo | Configuracion | Envia correo real o muestra simulado. |

## Seguridad y privacidad

- No subir `.env`.
- No hardcodear contrasenas.
- No compartir API Keys.
- Ejecutar captura solo en redes autorizadas.
- Revisar permisos de `data/` y `logs/`.
- Recordar que DNS muestra dominios, no URLs completas HTTPS.
- WHOIS puede mostrar datos publicos de terceros; usar con fines defensivos.

## Limitaciones

- No reemplaza un IDS empresarial.
- DNS over HTTPS puede ocultar consultas DNS.
- La MAC puede no estar disponible fuera del segmento local.
- WHOIS puede no entregar ASN, pais, proveedor o abuse contact.
- La deteccion de IP peligrosa depende de la blacklist local.
- SMTP puede fallar por credenciales, firewall, proveedor o politicas anti-spam.

## Troubleshooting

| Problema | Causa probable | Accion |
| --- | --- | --- |
| Scapy aparece como no instalado | Se ejecuto otro Python o se instalo Scrapy. | Use `venv/bin/python main.py` o reinstale `scapy`. |
| No captura paquetes | Falta permiso de socket crudo. | Use `sudo venv/bin/python main.py`. |
| No aparecen DNS | Interfaz incorrecta, DoH, cache DNS o poco trafico. | Cambie interfaz, genere trafico DNS, desactive DoH para prueba. |
| WHOIS falla | `whois` no instalado o bloqueo de red. | `sudo apt install whois`. |
| SMTP falla | Host/puerto/usuario/password incorrectos. | Revise `.env` y use contrasena de aplicacion. |
| Correo llega a spam | Proveedor o dominio sin reputacion. | Marque remitente confiable, revise SPF/DKIM. |
| JSON corrupto | Edicion manual invalida. | La app crea `.bak` y restaura estructura. |
| CSV no se actualiza | Permisos de escritura. | Revise permisos de `logs/`. |
| Avisos DBus con sudo | Tema grafico Qt bajo root. | No afectan al IDS; continuar usando la app. |

## Checklist de demostracion

1. Abrir con `python main.py` para revisar interfaz o `sudo venv/bin/python main.py` para captura real.
2. Mostrar Dashboard.
3. Mostrar Lista Blanca y registrar un equipo.
4. Abrir Trafico DNS/Sitios y generar evento de prueba.
5. Iniciar monitoreo si hay permisos.
6. Abrir Alertas y generar alerta de equipo no autorizado.
7. Generar alerta de IP peligrosa.
8. Mostrar detalle de alerta y WHOIS/Abuse.
9. Mostrar Threat Intelligence y blacklist.
10. Mostrar Configuracion y prueba de correo simulado.
11. Mostrar CSV actualizados.
12. Mostrar `.env.example` sin exponer `.env`.

## Mejoras futuras

- Integrar AbuseIPDB.
- Integrar VirusTotal.
- Exportar reportes PDF.
- Crear graficas historicas.
- Firmar digitalmente logs.
- Cifrar configuracion sensible.
- Integrar bloqueo automatico con firewall.
- Agregar reglas de correlacion avanzadas.
