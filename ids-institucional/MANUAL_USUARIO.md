# IDS Institucional - Manual de Usuario

Sistema operativo recomendado: Debian Linux  
Version del sistema: entrega academica final  
Correo administrador por defecto: `al281268@edu.uaa.mx`

## Introduccion

IDS Institucional es una aplicacion de monitoreo defensivo. Permite registrar equipos autorizados, observar consultas DNS, detectar equipos desconocidos, identificar conexiones hacia IPs peligrosas, generar alertas y guardar evidencia en archivos CSV.

El sistema esta pensado para redes autorizadas y fines academicos. No debe usarse en redes ajenas.

## Requisitos

- Debian Linux.
- Python 3.
- Entorno virtual `venv`.
- `libpcap-dev`.
- `tcpdump`.
- `whois`.
- `openssl`.
- Acceso a red.
- Permisos de administrador para captura real.
- Cuenta SMTP si se desean correos reales.

## Instalacion

Abra una terminal dentro de la carpeta del proyecto y ejecute:

```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv libpcap-dev tcpdump whois openssl -y
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python main.py
```

Para captura real de paquetes:

```bash
sudo venv/bin/python main.py
```

## Configuracion inicial

Al iniciar, la aplicacion crea automaticamente:

- `data/whitelist.json`
- `data/blacklist_ips.json`
- `data/settings.json`
- `logs/traffic_log.csv`
- `logs/alerts_log.csv`
- `logs/forensic_log.csv`
- `logs/system_events.csv`

Si un archivo falta, se crea. Si un JSON esta corrupto, se respalda con extension `.bak` y se regenera.

## Configuracion de correo

El correo administrador predeterminado es:

```text
al281268@edu.uaa.mx
```

Puede cambiarse en:

- Pestana Configuracion.
- Variable `ADMIN_EMAIL` del archivo `.env`.
- Campo `admin_email` de `data/settings.json`.

Para crear `.env`, use la pestana Configuracion o copie `.env.example`.

Plantilla recomendada:

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

`SMTP_ENABLED=false` significa modo simulado: no envia correo real. `SMTP_ENABLED=true` intenta enviar correo real. Nunca comparta `.env` ni lo suba a GitHub.

Si se usa Microsoft 365 institucional, puede requerirse SMTP AUTH, permiso del administrador, contrasena de aplicacion si la organizacion lo permite y revision de seguridad. Si falla el correo, el IDS sigue funcionando y registra el error.

## Ejecucion

Para revisar la interfaz o usar demo:

```bash
source venv/bin/activate
python main.py
```

Para monitoreo real:

```bash
sudo venv/bin/python main.py
```

## Ventana principal

La aplicacion tiene navegacion lateral:

- Dashboard.
- Lista Blanca.
- Trafico DNS/Sitios.
- Alertas.
- Threat Intelligence.
- Configuracion.

## Dashboard

Muestra el estado general del IDS:

- Captura activa, detenida o en error.
- Total de eventos DNS.
- Equipos autorizados.
- Alertas totales.
- Alertas criticas y de emergencia.
- IPs peligrosas cargadas.
- Eventos por minuto.
- Actividad reciente y timeline.

Si el estado indica error, revise `logs/system_events.csv`.

## Lista Blanca

La lista blanca contiene equipos autorizados por IP y MAC.

Para agregar:

1. Abra Lista Blanca.
2. Escriba nombre del equipo.
3. Escriba IP, por ejemplo `192.168.1.25`.
4. Escriba MAC, por ejemplo `AA:BB:CC:DD:EE:01`.
5. Agregue descripcion.
6. Pulse Agregar equipo.

Para editar:

1. Seleccione una fila.
2. Modifique campos.
3. Pulse Editar seleccionado.

Para eliminar:

1. Seleccione una fila.
2. Pulse Eliminar seleccionado.

El sistema no acepta nombre vacio, IP invalida, MAC invalida, IP duplicada ni MAC duplicada.

## Trafico DNS/Sitios

Esta pestana registra dominios consultados por DNS.

Para monitoreo real:

1. Ejecute con `sudo venv/bin/python main.py`.
2. Seleccione interfaz.
3. Pulse Iniciar monitoreo.
4. Genere trafico DNS:

```bash
nslookup debian.org
nslookup python.org
```

5. Verifique la tabla y `logs/traffic_log.csv`.
6. Pulse Detener monitoreo al finalizar.

Para demo, pulse Generar evento de prueba.

## Alertas

Una alerta indica un evento relevante:

- `INFO`: evento informativo.
- `WARNING`: riesgo medio o inconsistencia.
- `CRITICAL`: evento critico.
- `EMERGENCY`: IP peligrosa o evento prioritario.

La pestana permite:

- Recargar alertas.
- Limpiar vista.
- Marcar como revisada.
- Consultar WHOIS nuevamente.
- Generar alerta de equipo no autorizado.
- Generar alerta de IP peligrosa.

El detalle muestra IP origen, MAC origen, IP destino, severidad, estado, mensaje y datos WHOIS si existen.

## Threat Intelligence

La blacklist local se guarda en `data/blacklist_ips.json`. Una IP peligrosa representa infraestructura asociada a botnet, malware u otra actividad sospechosa.

Para agregar una IP:

1. Abra Threat Intelligence.
2. Escriba IP.
3. Escriba tipo de riesgo, por ejemplo Botnet o Malware.
4. Seleccione severidad.
5. Escriba fuente.
6. Escriba descripcion.
7. Pulse Agregar IP.

Tambien puede editar, eliminar, recargar, probar IP, consultar WHOIS y generar una alerta EMERGENCY de prueba.

## Automatizacion forense

WHOIS ayuda a obtener datos publicos de una IP:

- ASN.
- Pais.
- Proveedor u organizacion.
- Abuse Contact.

Si no hay internet, `whois` no esta instalado o el servidor no devuelve datos, la aplicacion no se cierra. Guarda un resultado controlado en `logs/forensic_log.csv`.

Instalacion de WHOIS:

```bash
sudo apt install whois
```

## Configuracion

La pestana Configuracion permite editar:

- Correo administrador.
- SMTP habilitado o simulado.
- STARTTLS.
- Host SMTP.
- Puerto SMTP.
- Usuario SMTP.
- Password SMTP.
- Remitente.
- Cooldown de alertas.
- Interfaz de captura.

Tambien permite crear `.env` desde plantilla y probar correo. En modo simulado, la prueba no envia correo real.

## Archivos generados

- `whitelist.json`: equipos autorizados.
- `blacklist_ips.json`: IPs peligrosas.
- `settings.json`: preferencias no sensibles.
- `traffic_log.csv`: consultas DNS.
- `alerts_log.csv`: alertas.
- `forensic_log.csv`: resultados WHOIS.
- `system_events.csv`: eventos tecnicos y errores controlados.

## Modo demo para exposicion

1. Abra la aplicacion con `python main.py`.
2. Muestre Dashboard.
3. Agregue un equipo en Lista Blanca.
4. Genere evento DNS simulado.
5. Genere alerta de equipo no autorizado.
6. Genere alerta de IP peligrosa.
7. Consulte WHOIS desde Alertas o Threat Intelligence.
8. Muestre los CSV en `logs/`.
9. Abra Configuracion y muestre SMTP simulado.
10. Muestre `.env.example` sin contrasenas reales.

## Troubleshooting

Error: La aplicacion no abre.  
Causa posible: PyQt6 no esta instalado o el entorno virtual no esta activo.  
Solucion:

```bash
source venv/bin/activate
pip install -r requirements.txt
python main.py
```

Error: No se puede capturar trafico.  
Causa posible: permisos insuficientes.  
Solucion:

```bash
sudo venv/bin/python main.py
```

Error: No aparece trafico DNS.  
Causas posibles: interfaz incorrecta, no hay trafico, DNS over HTTPS activo o VM sin modo puente.  
Solucion:

```bash
ip link show
nslookup debian.org
```

Cambie interfaz en Configuracion o en Trafico DNS/Sitios.

Error: El correo no llega.  
Causas posibles: `SMTP_ENABLED=false`, credenciales incorrectas, Microsoft 365 bloquea SMTP, SMTP AUTH deshabilitado o correo en spam.  
Solucion: revise `.env`, active `SMTP_ENABLED=true` solo con credenciales reales, confirme SMTP AUTH y revise spam.

Error: WHOIS no funciona.  
Solucion:

```bash
sudo apt install whois
```

Error: JSON corrupto.  
Solucion: revise el archivo en `data/`, busque respaldo `.bak` y reinicie la aplicacion.

Error: CSV no se actualiza.  
Solucion: revise permisos de `logs/`, ejecute desde la carpeta del proyecto y confirme que el archivo no este abierto con bloqueo externo.

Error: No se guardan cambios.  
Solucion: verifique permisos de escritura en `data/` y que no se este ejecutando desde una copia distinta.

Error: No se ven alertas.  
Solucion: genere una alerta demo, revise cooldown y confirme `logs/alerts_log.csv`.

Error: App se cierra inesperadamente.  
Solucion: ejecutela desde terminal y revise `logs/system_events.csv`.

## Buenas practicas

- Usar solo en redes autorizadas.
- No compartir `.env`.
- No compartir logs fuera del contexto academico.
- No autorizar equipos desconocidos sin verificar.
- Revisar alertas criticas y de emergencia.
- Mantener respaldos de `data/` y `logs/`.
- Detener monitoreo antes de cerrar si esta activo.

## Cierre

IDS Institucional esta disenado para monitoreo defensivo academico. Su valor principal es mostrar un flujo completo: autorizacion IP/MAC, DNS, alertas, evidencias CSV, WHOIS y SMTP configurable sin credenciales hardcodeadas.
