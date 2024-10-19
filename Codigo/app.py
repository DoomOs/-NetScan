import os
import nmap
from scapy.all import ARP, Ether, srp, sniff
from flask import Flask, jsonify, render_template, send_file
import json
import socket
from scapy.contrib.lldp import LLDPDU
from scapy.layers.l2 import Dot3
import requests
from io import BytesIO
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor
import asyncio
from aiohttp import ClientSession



app = Flask(__name__)


# Carga la base de datos de MAC una sola vez al inicio
if not os.getenv('SPHINX_BUILD'):
    with open('mac-vendors-export.json', 'r', encoding='utf-8') as f:
        mac_vendors = json.load(f)

def get_local_ip():
    """
    Obtiene la dirección IP local de la máquina actual.

    Returns:
        str: Dirección IP local si se puede obtener, o None si ocurre un error.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception as e:
        print(f"Error al obtener la IP local: {e}")
        return None

local_ip = get_local_ip()
print(f"La dirección IP local es: {local_ip}")

@lru_cache(maxsize=1024)
def obtener_fabricante(mac):
    """
    Obtiene el nombre del fabricante basado en la dirección MAC.

    Parameters:
        mac (str): Dirección MAC en formato de cadena sin separadores.

    Returns:
        str: Nombre del fabricante si se encuentra en la base de datos, 'Desconocido' si no.
    """
    mac_prefix = mac[:8].upper()
    for vendor in mac_vendors:
        if mac_prefix.startswith(vendor['macPrefix'].replace(':', '')):
            return vendor['vendorName']
    return 'Desconocido'

def escanear_red():
    """
    Escanea la red local para detectar dispositivos conectados, sus direcciones IP, MAC y fabricantes.

    Returns:
        list[dict]: Lista de diccionarios con información de dispositivos:
            - ip (str): Dirección IP del dispositivo.
            - mac (str): Dirección MAC del dispositivo.
            - fabricante (str): Nombre del fabricante del dispositivo.
            - es_switch (bool): Indica si el dispositivo es un switch (opcional).
    """
    dispositivos = []
    arp = ARP(pdst="192.168.1.0/24")
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    resultado = srp(ether/arp, timeout=3, verbose=False)[0]
    
    for enviado, recibido in resultado:
        mac = recibido.hwsrc
        ip = recibido.psrc
        fabricante = obtener_fabricante(mac.replace(':', ''))
        dispositivos.append({'ip': ip, 'mac': mac, 'fabricante': fabricante})
    
    def detect_network_devices():
        stp_macs = ["01:80:c2:00:00:00", "01:00:0c:cc:cc:cd"]
        stp_result = sniff(filter="ether dst " + " or ".join(stp_macs), timeout=5)
        lldp_result = sniff(filter="ether proto 0x88cc", timeout=5)
        cdp_result = sniff(filter="ether dst 01:00:0c:cc:cc:cc", timeout=5)
        return len(stp_result) > 0 or len(lldp_result) > 0 or len(cdp_result) > 0

    if detect_network_devices():
        possible_switch = next((d for d in dispositivos if d['fabricante'].lower() in ['cisco', 'juniper', 'hp', 'aruba', 'netgear']), None)
        if possible_switch:
            possible_switch['es_switch'] = True

    return dispositivos

@lru_cache(maxsize=128)
def escaneo_nmap(ip):
    """
    Realiza un escaneo de puertos y detección de sistema operativo en un dispositivo dado.

    Parameters:
        ip (str): Dirección IP del dispositivo a escanear.

    Returns:
        dict: Información detallada del dispositivo:
            - sistema_operativo (str): Nombre del sistema operativo detectado.
            - nombre_host (str): Nombre del host.
            - fabricante (str): Fabricante detectado del dispositivo.
            - puertos_abiertos (list[dict]): Información sobre puertos abiertos.
                - puerto (int): Número de puerto.
                - servicio (str): Nombre del servicio.
                - version (str): Versión del servicio.
                - banner (str): Información adicional del servicio.
        None: Si ocurre un error durante el escaneo.
    """
    nm = nmap.PortScanner()
    try:
        nm.scan(ip, arguments='-O -sV -sC')
        
        if ip in nm.all_hosts():
            coincidencia_os = nm[ip]['osmatch'][0] if 'osmatch' in nm[ip] and nm[ip]['osmatch'] else {'name': 'Desconocido'}
            puertos_abiertos = [
                {
                    'puerto': puerto, 
                    'servicio': nm[ip]['tcp'][puerto]['name'],
                    'version': nm[ip]['tcp'][puerto]['version'],
                    'banner': nm[ip]['tcp'][puerto]['product']
                } 
                for puerto in nm[ip].get('tcp', {}) 
                if nm[ip]['tcp'][puerto]['state'] == 'open'
            ]
            
            return {
                'sistema_operativo': coincidencia_os['name'],
                'nombre_host': nm[ip].hostname() or 'Desconocido',
                'fabricante': nm[ip]['vendor'].get(nm[ip]['addresses'].get('mac'), 'Desconocido'),
                'puertos_abiertos': puertos_abiertos
            }
    except Exception as e:
        print(f"Error al escanear {ip}: {str(e)}")
        return None

async def fetch_vulnerabilities(session, keyword):
    """
    Busca vulnerabilidades conocidas para un servicio en la base de datos NVD.

    Parameters:
        session (ClientSession): Sesión de cliente HTTP asíncrona.
        keyword (str): Palabra clave para buscar vulnerabilidades.

    Returns:
        list[dict]: Lista de vulnerabilidades encontradas.
            - cve (str): ID del CVE.
            - descripcion (str): Descripción de la vulnerabilidad.
            - cvss_v3_score (float): Puntuación CVSS v3 de la vulnerabilidad.
    """
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}&resultsPerPage=10"
    async with session.get(url) as response:
        if response.status == 200:
            data = await response.json()
            vulnerabilidades = []
            for item in data.get('vulnerabilities', []):
                cve = item['cve']
                cve_id = cve['id']
                descripcion = cve['descriptions'][0]['value'] if cve['descriptions'] else "No description available"
                cvss_v3_score = next((metric['baseScore'] for metric in cve.get('metrics', {}).get('cvssMetricV31', []) if 'baseScore' in metric), None)
                vulnerabilidades.append({
                    'cve': cve_id, 
                    'descripcion': descripcion,
                    'cvss_v3_score': cvss_v3_score
                })
            return vulnerabilidades
    return []

@lru_cache(maxsize=128)
def buscar_vulnerabilidades(servicio, version):
    """
    Busca vulnerabilidades asociadas a un servicio y versión específicos.

    Parameters:
        servicio (str): Nombre del servicio.
        version (str): Versión del servicio.

    Returns:
        list[dict]: Lista de vulnerabilidades encontradas con detalles.
    """
    keyword = f"{servicio} {version}"
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    async def fetch():
        async with ClientSession() as session:
            return await fetch_vulnerabilities(session, keyword)
    return loop.run_until_complete(fetch())

def identificar_tipo_dispositivo(info_dispositivo, fabricante, ip, es_switch=False):
    """
    Identifica el tipo de dispositivo basado en la información obtenida.

    Parameters:
        info_dispositivo (dict): Información del dispositivo obtenida por Nmap.
        fabricante (str): Nombre del fabricante.
        ip (str): Dirección IP del dispositivo.
        es_switch (bool): Indica si el dispositivo es un switch.

    Returns:
        str: Tipo de dispositivo ('router', 'switch', 'dispositivo' o 'desconocido').
    """
    if ip == local_ip:
        return 'dispositivo'
    if es_switch:
        return 'switch'
    if info_dispositivo is None:
        return 'router' if 'router' in fabricante.lower() else 'desconocido'
    
    if 'Router' in info_dispositivo['sistema_operativo'] or any(puerto['puerto'] in [80, 443, 53] for puerto in info_dispositivo['puertos_abiertos']):
        return 'router'
    elif 'Switch' in info_dispositivo['sistema_operativo'] or any(puerto['puerto'] in [22, 23] for puerto in info_dispositivo['puertos_abiertos']):
        return 'switch'
    return 'dispositivo'

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/vulnerabilidades/<ip>', methods=['GET'])
def obtener_vulnerabilidades(ip):
    """
    Obtiene las vulnerabilidades asociadas a un dispositivo escaneado por su IP.

    Parameters:
        ip (str): Dirección IP del dispositivo.

    Returns:
        Response: Respuesta JSON con la lista de vulnerabilidades encontradas para cada puerto abierto.
    """
    # Usar la cache en la función para evitar repetir el escaneo
    info_dispositivo = escaneo_nmap(ip)
    if info_dispositivo:
        vulnerabilidades_por_puerto = []
        for puerto in info_dispositivo['puertos_abiertos']:
            vulnerabilidades = buscar_vulnerabilidades(puerto['servicio'], puerto['version'])
            vulnerabilidades_por_puerto.append({
                'puerto': puerto['puerto'],
                'servicio': puerto['servicio'],
                'version': puerto['version'],
                'banner': puerto['banner'],
                'vulnerabilidades': vulnerabilidades
            })
        return jsonify(vulnerabilidades_por_puerto)
    return jsonify([])


@app.route('/escanear', methods=['GET'])
def escanear():
    """
    Escanea la red para detectar dispositivos y genera datos de topología.

    Returns:
        Response: Respuesta JSON con la lista de dispositivos encontrados y la estructura de la red.
    """
    
    dispositivos = escanear_red()
    datos_red = {'nodes': [], 'edges': []}
    
    routers, switches, otros_dispositivos = [], [], []

    with ThreadPoolExecutor() as executor:
        futures = {executor.submit(escaneo_nmap, dispositivo['ip']): i for i, dispositivo in enumerate(dispositivos)}
        for future in futures:
            i = futures[future]
            dispositivo = dispositivos[i]
            info_dispositivo = future.result()
            tipo_dispositivo = identificar_tipo_dispositivo(info_dispositivo, dispositivo['fabricante'], dispositivo['ip'], dispositivo.get('es_switch', False))
            
            nodo = {
                'id': i,
                'label': f"{dispositivo['fabricante'] if info_dispositivo and info_dispositivo['nombre_host'] == 'Desconocido' else (info_dispositivo['nombre_host'] if info_dispositivo else dispositivo['fabricante'])}\n{dispositivo['ip']}",
                'title': f"IP: {dispositivo['ip']}<br>MAC: {dispositivo['mac']}<br>Fabricante: {dispositivo['fabricante']}"
                         f"{'<br>SO: ' + info_dispositivo['sistema_operativo'] if info_dispositivo else ''}"
                         f"{'<br>Puertos abiertos: ' + ', '.join([f'{p['puerto']}/{p['servicio']}' for p in info_dispositivo['puertos_abiertos']]) if info_dispositivo and info_dispositivo['puertos_abiertos'] else ''}",
                'shape': 'box' if tipo_dispositivo == 'switch' else 'triangle' if tipo_dispositivo == 'router' else 'ellipse',
                'color': {'background': 'red' if tipo_dispositivo == 'router' else 'lightgreen' if tipo_dispositivo == 'switch' else 'lightblue'}
            }
            
            datos_red['nodes'].append(nodo)
            
            if tipo_dispositivo == 'router':
                routers.append(i)
            elif tipo_dispositivo == 'switch':
                switches.append(i)
            else:
                otros_dispositivos.append(i)
    
    if routers:
        router_principal = routers[0]
        datos_red['edges'].extend({'from': router_principal, 'to': switch} for switch in switches)
        datos_red['edges'].extend({'from': switches[0] if switches else router_principal, 'to': dispositivo} for dispositivo in otros_dispositivos)
    elif switches:
        switch_principal = switches[0]
        datos_red['edges'].extend({'from': switch_principal, 'to': dispositivo} for dispositivo in otros_dispositivos)
    
    return jsonify({
        'dispositivos': dispositivos,
        'datos_red': datos_red
    })

def agregar_texto(p, texto, x, y, font_size=10, color=colors.black, salto_linea=14, max_width=500):
    """
    Agrega texto a un PDF respetando el ancho máximo y la posición.

    Parameters:
        p (canvas.Canvas): Objeto de canvas de ReportLab.
        texto (str): Texto a agregar al PDF.
        x (float): Posición X de inicio.
        y (float): Posición Y de inicio.
        font_size (int): Tamaño de la fuente del texto.
        color (Color): Color del texto.
        salto_linea (int): Espacio entre líneas de texto.
        max_width (int): Ancho máximo para ajustar el texto.

    Returns:
        float: Nueva posición Y después de agregar el texto.
    """
    p.setFont("Helvetica", font_size)
    p.setFillColor(color)
    width, height = letter
    margin = 0.5 * inch
    
    texto_lineas = p.beginText(x, y)
    texto_lineas.setFont("Helvetica", font_size)
    texto_lineas.setTextOrigin(x, y)
    texto_lineas.setFillColor(color)
    
    for linea in texto.split('\n'):
        palabras = linea.split()
        linea_actual = []
        for palabra in palabras:
            linea_actual.append(palabra)
            if p.stringWidth(' '.join(linea_actual), "Helvetica", font_size) >= max_width:
                linea_actual.pop()
                texto_lineas.textLine(' '.join(linea_actual))
                y -= salto_linea
                if y < margin:
                    p.drawText(texto_lineas)
                    p.showPage()
                    p.setFont("Helvetica", font_size)
                    texto_lineas = p.beginText(x, height - margin - 40)
                    y = height - margin - 40
                linea_actual = [palabra]
        if linea_actual:
            texto_lineas.textLine(' '.join(linea_actual))
            y -= salto_linea
        if y < margin:
            p.drawText(texto_lineas)
            p.showPage()
            texto_lineas = p.beginText(x, height - margin - 40)
            y = height - margin - 40

    p.drawText(texto_lineas)
    return y

@app.route('/generar_pdf/<ip>', methods=['GET'])
def generar_pdf(ip):
    """
    Genera un archivo PDF con las vulnerabilidades detectadas para un dispositivo específico.

    Parameters:
        ip (str): Dirección IP del dispositivo.

    Returns:
        Response: PDF generado con información sobre vulnerabilidades.
    """
    info_dispositivo = escaneo_nmap(ip)
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    
    width, height = letter
    margin = 0.5 * inch
    
    p.setTitle(f"Vulnerabilidades - {ip}")
    p.setFont("Helvetica-Bold", 12)
    
    x, y = margin, height - margin - 40
    
    y = agregar_texto(p, f"Vulnerabilidades para el dispositivo {ip}", x, y, font_size=12, color=colors.black)
    y -= 30
    
    if info_dispositivo:
        for puerto in info_dispositivo['puertos_abiertos']:
            vulnerabilidades = buscar_vulnerabilidades(puerto['servicio'], puerto['version'])
            
            y = agregar_texto(p, f"Puerto: {puerto['puerto']}", x, y, font_size=10, color=colors.darkblue)
            y = agregar_texto(p, f"Servicio: {puerto['servicio']} {puerto['version']}", x, y)
            y = agregar_texto(p, f"Banner: {puerto['banner']}", x, y)
            y -= 10
            
            for vuln in vulnerabilidades:
                y = agregar_texto(p, f"CVE: {vuln['cve']}", x + 20, y, font_size=9, color=colors.red)
                y = agregar_texto(p, f"Descripción: {vuln['descripcion']}", x + 20, y, font_size=9)
                y -= 10
            
            y -= 20

            if y < margin:
                p.showPage()
                y = height - margin - 40
    else:
        y = agregar_texto(p, "No se encontraron vulnerabilidades.", x, y)

    p.showPage()
    p.save()
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name=f"vulnerabilidades_{ip}.pdf", mimetype='application/pdf')

@app.route('/generar_pdf_todos', methods=['GET'])
def generar_pdf_todos():
    """
    Genera un archivo PDF con las vulnerabilidades detectadas para todos los dispositivos encontrados en la red.

    Returns:
        Response: PDF generado con información sobre vulnerabilidades de todos los dispositivos.
    """
    dispositivos = escanear_red()
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    
    width, height = letter
    margin = 0.5 * inch
    x, y = margin, height - margin - 40
    
    y = agregar_texto(p, "Vulnerabilidades de todos los dispositivos", x, y, font_size=12, color=colors.black)
    y -= 30
    
    for dispositivo in dispositivos:
        info_dispositivo = escaneo_nmap(dispositivo['ip'])
        if info_dispositivo:
            y = agregar_texto(p, f"Dispositivo: {dispositivo['ip']}", x, y, font_size=10, color=colors.darkblue)
            y -= 10
            
            for puerto in info_dispositivo['puertos_abiertos']:
                vulnerabilidades = buscar_vulnerabilidades(puerto['servicio'], puerto['version'])
                
                y = agregar_texto(p, f"Puerto: {puerto['puerto']}", x + 20, y)
                y = agregar_texto(p, f"Servicio: {puerto['servicio']} {puerto['version']}", x + 20, y)
                y -= 10
                
                for vuln in vulnerabilidades:
                    y = agregar_texto(p, f"CVE: {vuln['cve']}", x + 40, y, font_size=9, color=colors.red)
                    y = agregar_texto(p, f"Descripción: {vuln['descripcion']}", x + 40, y, font_size=8, color=colors.black)
                    y -= 10

                y -= 10

            y -= 20
            if y < margin:
                p.showPage()
                y = height - margin - 40
    
    p.save()
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name="vulnerabilidades_dispositivos.pdf", mimetype='application/pdf')

if __name__ == '__main__':
    app.run(debug=True)