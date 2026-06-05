# IDS Institucional

IDS Institucional es la primera fase de una herramienta defensiva para Debian Linux orientada a administradores de red. La aplicacion prepara una base visual, modular y escalable para monitorear trafico, revisar equipos autorizados, registrar consultas DNS, consultar indicadores de amenaza y documentar evidencia forense sin usar SQL ni bases de datos.

## Objetivos del IDS

- Monitorear trafico de red en entornos institucionales autorizados.
- Detectar IP y MAC no autorizadas contra una lista blanca local.
- Registrar dominios visitados mediante eventos DNS.
- Correlacionar destinos contra listas negras o APIs de Threat Intelligence.
- Preparar consultas forenses WHOIS, ASN, pais, proveedor y contactos Abuse.
- Enviar alertas por correo en fases posteriores.
- Mantener configuracion y bitacoras simples, auditables y portables.

## Alcance de esta primera fase

Esta fase no captura paquetes reales todavia. Entrega una aplicacion PyQt6 funcional con datos conectados a archivos JSON y CSV reales, creacion automatica de archivos faltantes, validaciones basicas de IP/MAC, navegacion visual completa y modulos preparados para integrar Scapy, consultas externas y alertas SMTP.

## Tecnologias utilizadas

- Python 3
- PyQt6 para la interfaz grafica
- Scapy como dependencia preparada para captura de paquetes
- JSON para configuracion, whitelist y blacklist
- CSV para bitacoras operativas
- python-dotenv para variables sensibles
- requests para futuras APIs de Threat Intelligence
- python-whois y herramientas Debian `whois` para consultas forenses posteriores

## Por que Debian Linux

Debian ofrece estabilidad, repositorios conservadores, buen soporte para Python 3, libpcap, tcpdump, whois y despliegues institucionales. Es una base adecuada para servicios defensivos donde importan trazabilidad, mantenimiento, permisos claros y compatibilidad con herramientas de red.

## Por que JSON/CSV y no SQL

Esta fase evita SQL por requisito de arquitectura y para mantener los datos auditables desde archivos planos. JSON permite editar configuraciones y listas de control con claridad. CSV facilita revisar bitacoras desde terminal, hojas de calculo o scripts forenses sin depender de un motor de base de datos.

## Estructura de carpetas

```text
ids-institucional/
├── README.md
├── requirements.txt
├── .env.example
├── main.py
├── app/
│   ├── __init__.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── packet_sniffer.py
│   │   ├── whitelist_manager.py
│   │   ├── dns_monitor.py
│   │   ├── threat_intel.py
│   │   ├── forensic_lookup.py
│   │   ├── alert_manager.py
│   │   └── log_manager.py
│   ├── gui/
│   │   ├── __init__.py
│   │   ├── main_window.py
│   │   ├── dashboard_tab.py
│   │   ├── whitelist_tab.py
│   │   ├── traffic_tab.py
│   │   ├── alerts_tab.py
│   │   ├── threat_tab.py
│   │   ├── settings_tab.py
│   │   └── styles.py
│   └── utils/
│       ├── __init__.py
│       ├── validators.py
│       ├── network_utils.py
│       └── config_loader.py
├── data/
│   ├── whitelist.json
│   ├── blacklist_ips.json
│   └── settings.json
├── logs/
│   ├── traffic_log.csv
│   ├── alerts_log.csv
│   └── forensic_log.csv
└── assets/
    ├── logo_placeholder.png
    └── screenshots/
```

## Explicacion de modulos

- `main.py`: inicializa archivos requeridos, crea `QApplication` y abre la ventana principal.
- `app/core/packet_sniffer.py`: stub para futura captura con Scapy/libpcap.
- `app/core/whitelist_manager.py`: carga, agrega, edita y elimina equipos autorizados desde JSON.
- `app/core/dns_monitor.py`: punto de extension para parseo de eventos DNS.
- `app/core/threat_intel.py`: carga blacklist local y realiza consulta local simulada.
- `app/core/forensic_lookup.py`: prepara resultados forenses simulados para futura integracion WHOIS/Abuse.
- `app/core/alert_manager.py`: administra alertas y escritura futura en CSV.
- `app/core/log_manager.py`: lectura y escritura segura de bitacoras CSV.
- `app/gui/*`: ventanas, pestañas, tarjetas, tablas y estilos visuales.
- `app/utils/validators.py`: validacion de IP y MAC.
- `app/utils/network_utils.py`: datos locales del host.
- `app/utils/config_loader.py`: creacion automatica y lectura robusta de JSON/CSV.

## Instalacion en Debian

```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv libpcap-dev tcpdump whois openssl
cd ids-institucional
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python main.py
```

## Permisos de captura para fases posteriores

La captura real de paquetes normalmente requiere privilegios elevados o capacidades especificas. Para fases posteriores se debe evaluar una estrategia segura, por ejemplo ejecutar solo el componente de captura con permisos controlados, usar `setcap` sobre binarios concretos cuando aplique, o iniciar la aplicacion con permisos administrativos en entornos autorizados. No se recomienda ejecutar codigo innecesario como root.

## Variables de entorno

Las credenciales sensibles no deben guardarse en JSON ni en el codigo. Copie `.env.example` a `.env` y complete valores reales:

```bash
cp .env.example .env
```

Ejemplo:

```env
SMTP_USERNAME=admin@example.org
SMTP_PASSWORD=contraseña_segura
SMTP_FROM=ids@example.org
THREAT_INTEL_API_KEY=api_key_real
```

## Archivos JSON

- `data/whitelist.json`: lista de equipos autorizados con `id`, `device_name`, `ip`, `mac`, `description` y `created_at`.
- `data/blacklist_ips.json`: indicadores peligrosos con `ip`, `risk_type`, `severity`, `source` y `description`.
- `data/settings.json`: configuracion no sensible como correo administrador, interfaz de captura y banderas de monitoreo.

Si un JSON no existe, esta vacio o esta corrupto, la aplicacion lo recrea con estructura valida.

## Archivos CSV

- `logs/traffic_log.csv`: `date,time,src_ip,src_mac,domain,protocol,event_type`.
- `logs/alerts_log.csv`: `date,time,severity,src_ip,src_mac,dst_ip,risk_type,message,status`.
- `logs/forensic_log.csv`: `date,time,ip,asn,country,abuse_contact,provider,raw_summary`.

Los CSV se crean automaticamente con encabezados validos si faltan.

## Pestañas visuales

- Dashboard: tarjetas de estado, equipos autorizados, alertas criticas, dominios registrados, eventos recientes e indicador de monitoreo.
- Lista Blanca: tabla IP/MAC, formulario, validacion visual y acciones agregar, editar, eliminar y recargar.
- Trafico DNS/Sitios: tabla de dominios visitados, limpieza de vista y apertura del CSV.
- Alertas: tabla con colores por severidad y panel de detalle.
- Threat Intelligence: blacklist local, recarga y consulta manual simulada.
- Configuracion: correo administrador, SMTP, interfaz, API Key enmascarada y prueba visual simulada.

## Flujo general del sistema

1. `main.py` verifica estructura y archivos requeridos.
2. La interfaz carga configuracion, whitelist, blacklist y bitacoras.
3. El administrador revisa dashboard y tablas operativas.
4. Las acciones visuales modifican JSON o leen CSV segun corresponda.
5. En fases posteriores, Scapy alimentara eventos DNS, alertas y consultas forenses.

## Estado actual

- Interfaz PyQt6 funcional.
- Navegacion lateral completa.
- Datos iniciales en JSON/CSV.
- Creacion automatica de archivos faltantes.
- Validacion IP/MAC basica.
- Captura real, consultas externas y envio SMTP quedan preparados pero no activos.

## Proximas fases planeadas

- Captura real con Scapy en interfaz Debian seleccionable.
- Deteccion de IP/MAC no autorizadas.
- Registro DNS desde paquetes reales.
- Correlacion con feeds externos y APIs de Threat Intelligence.
- Consultas WHOIS/Abuse automatizadas.
- Alertas SMTP con plantillas y control de frecuencia.
- Exportes forenses y endurecimiento operativo.

## Buenas practicas de seguridad

- No hardcodear contraseñas.
- No subir `.env` a GitHub.
- Mantener `.env.example` sin secretos reales.
- Proteger API Keys y rotarlas cuando sea necesario.
- Ejecutar monitoreo solo en redes propias o autorizadas.
- Revisar permisos de archivos JSON/CSV en entornos compartidos.

## Troubleshooting

- Si PyQt6 no instala, verifique que el entorno virtual este activo y que Debian tenga paquetes graficos requeridos.
- Si la ventana no abre en un servidor sin escritorio, use una sesion grafica local o X11/Wayland correctamente configurado.
- Si `python main.py` falla por modulo no encontrado, ejecute `pip install -r requirements.txt` dentro del venv.
- Si los archivos de datos se dañan, la aplicacion intenta recrearlos con estructura valida.
- Si la futura captura no ve paquetes, revise permisos, interfaz seleccionada y dependencias `libpcap-dev`/`tcpdump`.

## Ejecucion

```bash
python main.py
```

## Advertencia legal

El monitoreo de red debe realizarse solo en redes propias, institucionales o donde exista autorizacion explicita. El uso indebido de herramientas IDS o captura de paquetes puede violar leyes, contratos o politicas internas.
