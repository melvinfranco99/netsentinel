# NetSentinel

Escáner de red y auditor de seguridad para Linux, en español. Descubre los dispositivos de tu red, identifica sus servicios y versiones, detecta las vulnerabilidades y malas configuraciones más habituales y **te explica cómo solucionar cada una**.

Sin dependencias: solo Python 3.10+ y herramientas estándar de Linux. No necesita root.

> ⚠️ Úsalo solo en redes que te pertenezcan o que tengas permiso explícito para analizar.

## Instalación

```bash
curl -fsSL https://raw.githubusercontent.com/melvinfranco99/netsentinel/main/install.sh | bash
```

o desde el repositorio:

```bash
git clone https://github.com/melvinfranco99/netsentinel.git && cd netsentinel && ./install.sh
```

Se instala en `~/.local/share/netsentinel` con el comando `~/.local/bin/netsentinel`. Para desinstalar: `./uninstall.sh` (`--purge` borra también el historial).

## Uso

```bash
netsentinel scan                                   # escanea tu red local (perfil estándar)
netsentinel scan 192.168.1.0/24 -p completo        # los 65 535 puertos
netsentinel scan 10.0.0.1-50 --ports 22,80,443     # rango y puertos a medida
netsentinel scan -d --html informe.html            # detalle completo + informe HTML (imprimible a PDF)
netsentinel audit                                  # auditoría de seguridad de este equipo
netsentinel net                                    # interfaces, gateway, DNS y Wi-Fi
netsentinel history                                # historial de escaneos
netsentinel report ultimo --html informe.html      # exportar un escaneo guardado (HTML, CSV o JSON)
```

Perfiles: `rapido` (top 100 + IoT), `estandar` (top 1000 + IoT), `completo` (1-65535), `descubrimiento` (solo dispositivos).

## Qué hace

**Descubrimiento**: ARP sin privilegios, ICMP, TCP, mDNS/Bonjour, SSDP/UPnP, NetBIOS y DNS inverso. Fabricante por MAC (base de Wireshark), detección de MAC aleatorias, tipo de dispositivo (router, impresora, móvil, cámara, IoT, NAS…) y estimación del sistema operativo. Marca los dispositivos nuevos respecto a escaneos anteriores.

**Servicios**: banners y versiones de SSH, FTP, SMTP, HTTP/HTTPS, VNC, MySQL, SMB, RDP, Redis, MQTT, RTSP, Docker, Elasticsearch, etc. Analiza certificados TLS, protocolos y cifrados SSH.

**Vulnerabilidades** (comprobaciones no intrusivas, sin fuerza bruta):
- Protocolos inseguros: Telnet, FTP sin cifrar o anónimo, TFTP, rlogin/rsh, SMBv1, paneles de administración por HTTP.
- Accesos sin autenticación: Redis, MongoDB, Elasticsearch, Memcached, API de Docker, ADB, MQTT, VNC.
- Configuración débil: SNMP `public`/`private`, firma SMB, RDP sin NLA, UPnP IGD, cabeceras HTTP, HSTS, listado de directorios, ficheros sensibles expuestos (`.git`, `.env`…).
- Criptografía: TLS 1.0/1.1, cifrados anónimos/RC4/3DES, certificados caducados o débiles, algoritmos SSH obsoletos, Terrapin.
- Software vulnerable por versión (regreSSHion, Heartbleed, Apache 2.4.49/50, vsftpd 2.3.4, Winbox de MikroTik, RediShell, Misfortune Cookie…).
- Seguridad de la Wi-Fi (abierta, WEP, WPA/TKIP).

**Auditoría local**: cortafuegos, servicios expuestos, SSH, actualizaciones pendientes, reinicio pendiente, sysctl de endurecimiento, AppArmor/SELinux, Secure Boot, cifrado de disco, grupo docker, cuentas UID 0 y claves SSH sin contraseña.

Cada hallazgo incluye severidad, evidencia, impacto, pasos concretos para corregirlo y referencias (CVE/CWE). La red recibe una nota de A a F.

## Licencia

MIT. La base de fabricantes MAC se descarga del proyecto Wireshark en la instalación.
