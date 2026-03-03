from reportlab.lib.pagesizes import A4
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                 TableStyle, PageBreak, HRFlowable)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib.colors import black, red, white, HexColor
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from datetime import datetime
from pathlib import Path
from models.host import Host


# Colores del informe
DARK_BG = HexColor('#1a1a2e')
ACCENT = HexColor('#e94560')
LIGHT_BG = HexColor('#f5f5f5')
SUCCESS_GREEN = HexColor('#27ae60')
WARNING_ORANGE = HexColor('#f39c12')


class PDFReportGenerator:
    def __init__(self, host: Host):
        self.host = host
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.filename = Path(f"outputs/REPORT_{host.ip.replace('.', '_')}_{self.timestamp}.pdf")
        self.styles = getSampleStyleSheet()
        self._create_custom_styles()

    def _create_custom_styles(self):
        self.styles.add(ParagraphStyle(
            'CoverTitle', parent=self.styles['Title'],
            fontSize=24, spaceAfter=20, textColor=DARK_BG, alignment=TA_CENTER
        ))
        self.styles.add(ParagraphStyle(
            'CoverSubtitle', parent=self.styles['Normal'],
            fontSize=14, spaceAfter=10, textColor=HexColor('#555555'), alignment=TA_CENTER
        ))
        self.styles.add(ParagraphStyle(
            'SectionTitle', parent=self.styles['Heading1'],
            fontSize=16, textColor=DARK_BG, spaceAfter=12, spaceBefore=16
        ))
        self.styles.add(ParagraphStyle(
            'SubSection', parent=self.styles['Heading2'],
            fontSize=12, textColor=HexColor('#333333'), spaceAfter=8
        ))
        self.styles.add(ParagraphStyle(
            'BodyText', parent=self.styles['Normal'],
            fontSize=10, leading=14, alignment=TA_JUSTIFY, spaceAfter=6
        ))
        self.styles.add(ParagraphStyle(
            'AlertCritical', parent=self.styles['Normal'],
            fontSize=10, textColor=red, backColor=HexColor('#fff0f0'),
            borderPadding=5, spaceAfter=8
        ))
        self.styles.add(ParagraphStyle(
            'AlertSuccess', parent=self.styles['Normal'],
            fontSize=10, textColor=SUCCESS_GREEN, spaceAfter=8
        ))

    def _add_cover_page(self, story):
        """Portada del informe"""
        story.append(Spacer(1, 100))
        story.append(Paragraph("INFORME DE AUDITORÍA", self.styles['CoverTitle']))
        story.append(Paragraph("DE SEGURIDAD INFORMÁTICA", self.styles['CoverTitle']))
        story.append(Spacer(1, 30))
        story.append(HRFlowable(width="60%", thickness=2, color=ACCENT))
        story.append(Spacer(1, 30))
        story.append(Paragraph("Ethical Audit Framework v2.0", self.styles['CoverSubtitle']))
        story.append(Spacer(1, 20))

        info_data = [
            ['Objetivo', self.host.ip],
            ['Sistema Operativo', getattr(self.host, 'os_detection', 'No detectado')],
            ['Nivel de Riesgo', self.host.risk_level.value],
            ['Fecha del Análisis', datetime.now().strftime('%d/%m/%Y %H:%M')],
            ['Puertos Abiertos', str(len(self.host.ports_open))],
            ['Vulnerabilidades', str(len(self.host.vulnerabilities))],
            ['Credenciales Extraídas', str(len(self.host.credentials))],
        ]

        info_table = Table(info_data, colWidths=[150, 250])
        info_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('TEXTCOLOR', (0, 0), (0, -1), DARK_BG),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('LINEBELOW', (0, 0), (-1, -2), 0.5, HexColor('#dddddd')),
        ]))
        story.append(info_table)
        story.append(PageBreak())

    def _add_index(self, story):
        """Índice del informe"""
        story.append(Paragraph("ÍNDICE", self.styles['SectionTitle']))
        story.append(Spacer(1, 10))
        sections = [
            "1. Resumen Ejecutivo",
            "2. Metodología",
            "3. Herramientas Utilizadas",
            "4. Fase de Escaneo (Reconocimiento)",
            "5. Fase de Penetración: Fuerza Bruta (WordPress)",
            "6. Fase de Penetración: Inyección SQL (DVWA)",
            "7. Credenciales Extraídas",
            "8. Análisis de Riesgo",
            "9. Recomendaciones de Seguridad",
            "10. Conclusiones",
        ]
        for s in sections:
            story.append(Paragraph(s, self.styles['BodyText']))
        story.append(PageBreak())

    def _add_executive_summary(self, story):
        """Resumen ejecutivo"""
        story.append(Paragraph("1. RESUMEN EJECUTIVO", self.styles['SectionTitle']))
        story.append(HRFlowable(width="100%", thickness=1, color=ACCENT))
        story.append(Spacer(1, 10))

        n_crit = sum(1 for v in self.host.vulnerabilities if v.risk.name == 'CRITICAL')
        n_high = sum(1 for v in self.host.vulnerabilities if v.risk.name == 'HIGH')
        n_med = sum(1 for v in self.host.vulnerabilities if v.risk.name == 'MEDIUM')

        summary = f"""
        Se ha realizado una auditoría de seguridad informática completa sobre el sistema
        objetivo <b>{self.host.ip}</b>. El análisis ha incluido las fases de reconocimiento
        (escaneo de puertos y servicios), enumeración de directorios, pruebas de fuerza bruta
        contra WordPress, e inyección SQL contra DVWA.
        <br/><br/>
        <b>Resultados principales:</b><br/>
        - Se detectaron <b>{len(self.host.ports_open)} puertos abiertos</b> con servicios activos.<br/>
        - Se identificaron <b>{len(self.host.vulnerabilities)} vulnerabilidades</b>
          ({n_crit} críticas, {n_high} altas, {n_med} medias).<br/>
        - Se extrajeron <b>{len(self.host.credentials)} credenciales</b> mediante inyección SQL y/o fuerza bruta.<br/>
        - Se descubrieron <b>{len(getattr(self.host, 'directories', []))} directorios</b> web accesibles.<br/>
        - Sistema operativo detectado: <b>{getattr(self.host, 'os_detection', 'No detectado')}</b>.<br/>
        <br/>
        El nivel de riesgo global del sistema es: <b><font color="red">{self.host.risk_level.value}</font></b>.
        """
        story.append(Paragraph(summary, self.styles['BodyText']))
        story.append(Spacer(1, 15))

    def _add_methodology(self, story):
        """Metodología"""
        story.append(Paragraph("2. METODOLOGÍA", self.styles['SectionTitle']))
        story.append(HRFlowable(width="100%", thickness=1, color=ACCENT))
        story.append(Spacer(1, 10))

        text = """
        La auditoría se ha llevado a cabo siguiendo una metodología estructurada basada en
        estándares de hacking ético (OWASP, PTES), dividida en las siguientes fases:
        <br/><br/>
        <b>Fase 1 - Reconocimiento:</b> Escaneo de puertos, servicios y detección de sistema
        operativo mediante Nmap. Identificación de tecnologías web y enumeración de
        directorios con Gobuster/Dirb.<br/><br/>
        <b>Fase 2 - Fuerza Bruta (WordPress):</b> Enumeración de usuarios de WordPress
        mediante WPScan y ataque de fuerza bruta con diccionario (rockyou.txt) contra
        el formulario de login.<br/><br/>
        <b>Fase 3 - Inyección SQL:</b> Detección y explotación de vulnerabilidades de
        inyección SQL en DVWA mediante SQLMap. Dumping de bases de datos y extracción
        de credenciales almacenadas. Crackeo de hashes MD5.<br/><br/>
        <b>Fase 4 - Análisis de Riesgo:</b> Evaluación del riesgo global basada en las
        vulnerabilidades encontradas, puertos expuestos y credenciales comprometidas.<br/><br/>
        <b>Fase 5 - Informe:</b> Documentación completa de todos los hallazgos, evidencias
        recopiladas y recomendaciones de mitigación.
        """
        story.append(Paragraph(text, self.styles['BodyText']))
        story.append(Spacer(1, 10))

    def _add_tools(self, story):
        """Herramientas utilizadas"""
        story.append(Paragraph("3. HERRAMIENTAS UTILIZADAS", self.styles['SectionTitle']))
        story.append(HRFlowable(width="100%", thickness=1, color=ACCENT))
        story.append(Spacer(1, 10))

        tools_data = [
            ['Herramienta', 'Versión', 'Función'],
            ['Kali Linux', '2024.x', 'Sistema operativo para auditorías'],
            ['Nmap', '7.x', 'Escaneo de puertos, servicios y OS'],
            ['SQLMap', '1.x', 'Detección y explotación de SQLi'],
            ['WPScan', '3.x', 'Auditoría WordPress + fuerza bruta'],
            ['Gobuster/Dirb', '3.x', 'Enumeración de directorios web'],
            ['Python 3', '3.x', 'Framework de automatización'],
            ['ReportLab', '4.x', 'Generación de informes PDF'],
        ]

        tools_table = Table(tools_data, colWidths=[120, 70, 230])
        tools_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), DARK_BG),
            ('TEXTCOLOR', (0, 0), (-1, 0), white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#cccccc')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [white, LIGHT_BG]),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(tools_table)
        story.append(PageBreak())

    def _add_scanning_phase(self, story):
        """Fase de Escaneo"""
        story.append(Paragraph("4. FASE DE ESCANEO (RECONOCIMIENTO)", self.styles['SectionTitle']))
        story.append(HRFlowable(width="100%", thickness=1, color=ACCENT))
        story.append(Spacer(1, 10))

        story.append(Paragraph("4.1 Detección de Sistema Operativo", self.styles['SubSection']))
        os_text = f"""
        Mediante Nmap con el flag <b>-O</b> (OS detection), se ha identificado el sistema
        operativo del objetivo:<br/><br/>
        <b>Sistema Operativo:</b> {getattr(self.host, 'os_detection', 'No detectado')}<br/>
        <b>IP del objetivo:</b> {self.host.ip}
        """
        story.append(Paragraph(os_text, self.styles['BodyText']))
        story.append(Spacer(1, 10))

        # Puertos
        story.append(Paragraph("4.2 Puertos y Servicios Detectados", self.styles['SubSection']))

        if self.host.ports_open:
            desc = f"""
            Se han detectado <b>{len(self.host.ports_open)} puertos abiertos</b> en el sistema
            objetivo. A continuación se detallan los servicios encontrados:
            """
            story.append(Paragraph(desc, self.styles['BodyText']))
            story.append(Spacer(1, 6))

            port_data = [['Puerto', 'Estado', 'Servicio', 'Versión']]
            for port, info in sorted(self.host.ports_open.items()):
                ver = f"{info.get('product', '')} {info.get('version', '')}".strip()
                port_data.append([
                    f"{port}/tcp",
                    info['state'],
                    info['service'],
                    ver[:35] if ver else 'N/A'
                ])

            table = Table(port_data, colWidths=[65, 55, 100, 200])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), DARK_BG),
                ('TEXTCOLOR', (0, 0), (-1, 0), white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#cccccc')),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [white, LIGHT_BG]),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ]))
            story.append(table)
        else:
            story.append(Paragraph(
                "<font color='green'><b>Resultado:</b> No se detectaron puertos abiertos. "
                "El sistema no presenta servicios expuestos.</font>",
                self.styles['AlertSuccess']
            ))

        story.append(Spacer(1, 10))

        # Directorios
        story.append(Paragraph("4.3 Enumeración de Directorios (Gobuster)", self.styles['SubSection']))
        dirs = getattr(self.host, 'directories', [])
        if dirs:
            desc = f"Se han descubierto <b>{len(dirs)} directorios/rutas</b> web accesibles:"
            story.append(Paragraph(desc, self.styles['BodyText']))

            dir_data = [['Directorio', 'Código HTTP', 'Accesibilidad']]
            for d in dirs[:20]:
                status = d.get('status', '???')
                access = 'Accesible' if status == '200' else 'Redirigido' if status in ['301', '302'] else 'Prohibido' if status == '403' else 'Otro'
                dir_data.append([d.get('path', ''), status, access])

            dir_table = Table(dir_data, colWidths=[200, 80, 120])
            dir_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), DARK_BG),
                ('TEXTCOLOR', (0, 0), (-1, 0), white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#cccccc')),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [white, LIGHT_BG]),
            ]))
            story.append(dir_table)
        else:
            story.append(Paragraph(
                "<font color='green'><b>Resultado:</b> No se encontraron directorios "
                "adicionales expuestos. La estructura web no revela rutas ocultas.</font>",
                self.styles['AlertSuccess']
            ))

        story.append(PageBreak())

    def _add_bruteforce_phase(self, story):
        """Fase de Fuerza Bruta"""
        story.append(Paragraph("5. FASE DE PENETRACIÓN: FUERZA BRUTA (WORDPRESS)", self.styles['SectionTitle']))
        story.append(HRFlowable(width="100%", thickness=1, color=ACCENT))
        story.append(Spacer(1, 10))

        intro = """
        Se ha realizado un ataque de fuerza bruta contra la instalación de WordPress
        detectada en el servidor objetivo, utilizando la herramienta <b>WPScan</b> con
        el diccionario <b>rockyou.txt</b>. Este ataque busca descubrir contraseñas débiles
        en las cuentas de usuario de WordPress.
        <br/><br/>
        <b>Proceso realizado:</b><br/>
        1. Enumeración de usuarios de WordPress (--enumerate u)<br/>
        2. Detección de plugins vulnerables (--enumerate vp,ap)<br/>
        3. Ataque de fuerza bruta con diccionario rockyou.txt<br/>
        """
        story.append(Paragraph(intro, self.styles['BodyText']))
        story.append(Spacer(1, 8))

        # Resultados WordPress
        wp_vulns = [v for v in self.host.vulnerabilities if 'WORDPRESS' in v.name.upper() or 'WP' in v.name.upper()]
        wp_creds = [c for c in self.host.credentials if 'wp' in c.get('source', '').lower()]

        if wp_vulns or wp_creds:
            story.append(Paragraph(
                "<font color='red'><b>⚠ VULNERABILIDADES ENCONTRADAS EN WORDPRESS</b></font>",
                self.styles['AlertCritical']
            ))
            for v in wp_vulns:
                story.append(Paragraph(f"<b>[{v.risk.name}]</b> {v.description}", self.styles['BodyText']))
                if v.recommendations:
                    story.append(Paragraph(f"<i>Recomendación: {v.recommendations}</i>", self.styles['Italic']))
                story.append(Spacer(1, 4))

            if wp_creds:
                story.append(Paragraph("<b>Credenciales obtenidas por fuerza bruta:</b>", self.styles['BodyText']))
                for c in wp_creds:
                    story.append(Paragraph(
                        f"- Usuario: <b>{c['user']}</b> | Contraseña: <b>{c['password']}</b>",
                        self.styles['BodyText']
                    ))
        else:
            story.append(Paragraph(
                "<font color='green'><b>Resultado:</b> No se encontraron vulnerabilidades "
                "en WordPress. El ataque de fuerza bruta no tuvo éxito, lo que indica que "
                "las contraseñas utilizadas son robustas y no se encuentran en el diccionario "
                "rockyou.txt. No se detectaron plugins con vulnerabilidades conocidas.</font>",
                self.styles['AlertSuccess']
            ))

        story.append(Spacer(1, 15))

    def _add_sqli_phase(self, story):
        """Fase de Inyección SQL"""
        story.append(Paragraph("6. FASE DE PENETRACIÓN: INYECCIÓN SQL (DVWA)", self.styles['SectionTitle']))
        story.append(HRFlowable(width="100%", thickness=1, color=ACCENT))
        story.append(Spacer(1, 10))

        intro = """
        Se ha buscado un servidor web que utilice SQL como lenguaje del gestor de base de
        datos y se ha realizado un ataque de inyección SQL sobre DVWA (Damn Vulnerable Web
        Application) mediante la herramienta <b>SQLMap</b>.
        <br/><br/>
        <b>Proceso realizado:</b><br/>
        1. Login automático en DVWA con credenciales por defecto<br/>
        2. Configuración de seguridad en nivel LOW para demostrar la vulnerabilidad<br/>
        3. Inyección SQL en el parámetro <i>id</i> del módulo SQLi de DVWA<br/>
        4. Volcado (dump) de la base de datos <i>dvwa</i>, tabla <i>users</i><br/>
        5. Crackeo de hashes MD5 extraídos<br/>
        """
        story.append(Paragraph(intro, self.styles['BodyText']))
        story.append(Spacer(1, 8))

        sql_vulns = [v for v in self.host.vulnerabilities if 'SQL' in v.name.upper() or 'INJECT' in v.name.upper()]
        sql_creds = [c for c in self.host.credentials if 'sql' in c.get('source', '').lower()]

        if sql_vulns or sql_creds:
            story.append(Paragraph(
                "<font color='red'><b>⚠ INYECCIÓN SQL CONFIRMADA - VULNERABILIDAD CRÍTICA</b></font>",
                self.styles['AlertCritical']
            ))
            for v in sql_vulns:
                story.append(Paragraph(f"<b>[{v.risk.name}]</b> {v.description}", self.styles['BodyText']))
                story.append(Spacer(1, 4))
        else:
            story.append(Paragraph(
                "<font color='green'><b>Resultado:</b> No se detectaron vulnerabilidades "
                "de inyección SQL. Los parámetros de entrada están correctamente validados "
                "y/o se utilizan consultas parametrizadas (prepared statements). El sistema "
                "es resistente a este tipo de ataque.</font>",
                self.styles['AlertSuccess']
            ))

        story.append(PageBreak())

    def _add_credentials(self, story):
        """Credenciales extraídas"""
        story.append(Paragraph("7. CREDENCIALES EXTRAÍDAS", self.styles['SectionTitle']))
        story.append(HRFlowable(width="100%", thickness=1, color=ACCENT))
        story.append(Spacer(1, 10))

        if self.host.credentials:
            story.append(Paragraph(
                "<font color='red'><b>⚠ ALERTA CRÍTICA:</b> Se han extraído las siguientes "
                "credenciales del sistema objetivo. Esto demuestra que la seguridad del sistema "
                "está gravemente comprometida.</font>",
                self.styles['AlertCritical']
            ))
            story.append(Spacer(1, 8))

            cred_data = [['Fuente', 'Usuario', 'Contraseña / Hash', 'Crackeado']]
            for cred in self.host.credentials:
                cracked = 'SI' if cred.get('cracked') else 'NO'
                cred_data.append([
                    cred.get('source', 'N/A')[:22],
                    cred.get('user', 'N/A'),
                    cred.get('password', 'N/A')[:32],
                    cracked
                ])

            cred_table = Table(cred_data, colWidths=[110, 80, 190, 50])
            cred_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), ACCENT),
                ('TEXTCOLOR', (0, 0), (-1, 0), white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, black),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [HexColor('#fff5f5'), white]),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ]))
            story.append(cred_table)
            story.append(Spacer(1, 10))

            story.append(Paragraph(
                "<b>Impacto:</b> Un atacante con estas credenciales podría acceder al panel "
                "de administración, modificar contenido, extraer datos personales de usuarios "
                "y potencialmente escalar privilegios en el servidor.",
                self.styles['BodyText']
            ))
        else:
            story.append(Paragraph(
                "<font color='green'><b>Resultado:</b> No se extrajeron credenciales del sistema. "
                "Las contraseñas no fueron obtenidas ni mediante inyección SQL ni mediante "
                "fuerza bruta, lo que indica un nivel adecuado de protección de datos "
                "sensibles.</font>",
                self.styles['AlertSuccess']
            ))

        story.append(Spacer(1, 15))

    def _add_risk_analysis(self, story):
        """Análisis de riesgo"""
        story.append(Paragraph("8. ANÁLISIS DE RIESGO", self.styles['SectionTitle']))
        story.append(HRFlowable(width="100%", thickness=1, color=ACCENT))
        story.append(Spacer(1, 10))

        risk_text = f"""
        Tras analizar todos los hallazgos, se ha calculado un nivel de riesgo global basado
        en los siguientes criterios:<br/><br/>
        - Número y severidad de vulnerabilidades encontradas<br/>
        - Puertos peligrosos expuestos (FTP, SSH, MySQL, etc.)<br/>
        - Servicios HTTP/HTTPS expuestos<br/>
        - Credenciales comprometidas<br/>
        <br/>
        <b>Nivel de Riesgo Global: <font color="red">{self.host.risk_level.value}</font></b>
        """
        story.append(Paragraph(risk_text, self.styles['BodyText']))
        story.append(Spacer(1, 10))

        # Tabla resumen de vulnerabilidades por severidad
        risk_summary = [['Severidad', 'Cantidad', 'Descripción']]
        n_crit = sum(1 for v in self.host.vulnerabilities if v.risk.name == 'CRITICAL')
        n_high = sum(1 for v in self.host.vulnerabilities if v.risk.name == 'HIGH')
        n_med = sum(1 for v in self.host.vulnerabilities if v.risk.name == 'MEDIUM')
        n_low = sum(1 for v in self.host.vulnerabilities if v.risk.name == 'LOW')

        risk_summary.append(['CRITICO', str(n_crit), 'Explotación inmediata, acceso total al sistema'])
        risk_summary.append(['ALTO', str(n_high), 'Explotación probable, acceso parcial'])
        risk_summary.append(['MEDIO', str(n_med), 'Explotación posible con condiciones'])
        risk_summary.append(['BAJO', str(n_low), 'Riesgo menor, impacto limitado'])

        risk_table = Table(risk_summary, colWidths=[80, 70, 270])
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), DARK_BG),
            ('TEXTCOLOR', (0, 0), (-1, 0), white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#cccccc')),
            ('BACKGROUND', (0, 1), (-1, 1), HexColor('#ffcccc')),
            ('BACKGROUND', (0, 2), (-1, 2), HexColor('#ffe0cc')),
            ('BACKGROUND', (0, 3), (-1, 3), HexColor('#fff5cc')),
            ('BACKGROUND', (0, 4), (-1, 4), HexColor('#ccffcc')),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ]))
        story.append(risk_table)

        # Lista detallada de vulnerabilidades
        if self.host.vulnerabilities:
            story.append(Spacer(1, 15))
            story.append(Paragraph("8.1 Detalle de Vulnerabilidades", self.styles['SubSection']))
            for i, vuln in enumerate(self.host.vulnerabilities, 1):
                color = '#FF0000' if vuln.risk.name == 'CRITICAL' else '#FF8C00' if vuln.risk.name == 'HIGH' else '#FFD700'
                story.append(Paragraph(
                    f"<b>{i}. <font color='{color}'>[{vuln.risk.name}]</font></b> {vuln.name}",
                    self.styles['BodyText']
                ))
                story.append(Paragraph(f"    {vuln.description}", self.styles['BodyText']))
                if vuln.recommendations:
                    story.append(Paragraph(
                        f"    <i>Recomendación: {vuln.recommendations}</i>",
                        self.styles['Italic']
                    ))
                story.append(Spacer(1, 6))

        story.append(PageBreak())

    def _add_recommendations(self, story):
        """Recomendaciones"""
        story.append(Paragraph("9. RECOMENDACIONES DE SEGURIDAD", self.styles['SectionTitle']))
        story.append(HRFlowable(width="100%", thickness=1, color=ACCENT))
        story.append(Spacer(1, 10))

        recs = [
            ["CRÍTICA", "Actualizar WordPress y todos los plugins a la última versión estable disponible. "
             "Las versiones desactualizadas contienen vulnerabilidades conocidas con exploits públicos."],
            ["CRÍTICA", "Implementar prepared statements (consultas parametrizadas) en todas las consultas SQL. "
             "Esto previene completamente los ataques de inyección SQL."],
            ["CRÍTICA", "Cambiar todas las contraseñas comprometidas inmediatamente. Establecer una política "
             "de contraseñas robustas (mínimo 12 caracteres, mayúsculas, minúsculas, números y símbolos)."],
            ["ALTA", "Configurar el nivel de seguridad de DVWA a 'impossible' en entornos de producción. "
             "Idealmente, no exponer aplicaciones vulnerables de forma intencionada."],
            ["ALTA", "Implementar autenticación de dos factores (2FA) en WordPress y en todos los "
             "paneles de administración del sistema."],
            ["ALTA", "Instalar y configurar un WAF (Web Application Firewall) como ModSecurity para "
             "filtrar peticiones maliciosas antes de que lleguen a la aplicación."],
            ["MEDIA", "Restringir el acceso a MySQL (puerto 3306) únicamente desde localhost. "
             "No debe ser accesible desde la red externa."],
            ["MEDIA", "Deshabilitar XML-RPC en WordPress para prevenir ataques de fuerza bruta "
             "y DDoS a través de este protocolo."],
            ["MEDIA", "Implementar rate-limiting y bloqueo de IP tras múltiples intentos fallidos "
             "de login para prevenir ataques de fuerza bruta."],
            ["BAJA", "Establecer auditorías de seguridad periódicas (trimestrales) y monitoreo "
             "continuo de logs para detectar actividad sospechosa de forma temprana."],
        ]

        rec_data = [['Prioridad', 'Recomendación']]
        for pri, rec in recs:
            rec_data.append([pri, rec])

        rec_table = Table(rec_data, colWidths=[65, 365])
        rec_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), DARK_BG),
            ('TEXTCOLOR', (0, 0), (-1, 0), white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#cccccc')),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [white, LIGHT_BG]),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(rec_table)
        story.append(Spacer(1, 15))

    def _add_conclusions(self, story):
        """Conclusiones"""
        story.append(Paragraph("10. CONCLUSIONES", self.styles['SectionTitle']))
        story.append(HRFlowable(width="100%", thickness=1, color=ACCENT))
        story.append(Spacer(1, 10))

        has_vulns = len(self.host.vulnerabilities) > 0
        has_creds = len(self.host.credentials) > 0

        if has_vulns or has_creds:
            conclusion = f"""
            La auditoría de seguridad realizada sobre el sistema <b>{self.host.ip}</b> ha revelado
            múltiples vulnerabilidades de seguridad con un nivel de riesgo
            <b>{self.host.risk_level.value}</b>.
            <br/><br/>
            Se han detectado <b>{len(self.host.vulnerabilities)} vulnerabilidades</b> y se han
            extraído <b>{len(self.host.credentials)} credenciales</b> del sistema. Los principales
            vectores de ataque identificados son la inyección SQL y la fuerza bruta contra
            servicios web.
            <br/><br/>
            Es <b>imperativo</b> que la empresa implemente las recomendaciones señaladas en la
            sección 9 de este informe de forma prioritaria, especialmente aquellas clasificadas
            como CRÍTICAS y ALTAS, para mitigar los riesgos identificados y proteger la
            confidencialidad, integridad y disponibilidad de sus sistemas e información.
            <br/><br/>
            La auditoría se ha realizado siguiendo los principios del hacking ético, con
            autorización previa, y toda la información obtenida se ha tratado de forma
            confidencial.
            """
        else:
            conclusion = f"""
            La auditoría de seguridad realizada sobre el sistema <b>{self.host.ip}</b> no ha
            revelado vulnerabilidades explotables de forma directa. El sistema presenta un nivel
            de seguridad adecuado para los vectores de ataque probados.
            <br/><br/>
            No obstante, se recomienda mantener las actualizaciones al día y realizar auditorías
            periódicas como parte de una estrategia de seguridad proactiva.
            <br/><br/>
            La auditoría se ha realizado siguiendo los principios del hacking ético, con
            autorización previa, y toda la información obtenida se ha tratado de forma
            confidencial.
            """

        story.append(Paragraph(conclusion, self.styles['BodyText']))
        story.append(Spacer(1, 20))
        story.append(HRFlowable(width="100%", thickness=1, color=ACCENT))
        story.append(Spacer(1, 10))
        story.append(Paragraph(
            f"<i>Informe generado automáticamente por Ethical Audit Framework v2.0 | "
            f"{datetime.now().strftime('%d/%m/%Y %H:%M:%S')}</i>",
            self.styles['BodyText']
        ))
        story.append(Paragraph(
            "<i>Toda la evidencia recopilada se encuentra en el directorio outputs/</i>",
            self.styles['BodyText']
        ))

    def generate(self):
        doc = SimpleDocTemplate(
            str(self.filename), pagesize=A4,
            topMargin=2 * cm, bottomMargin=2 * cm,
            leftMargin=2 * cm, rightMargin=2 * cm
        )
        story = []

        self._add_cover_page(story)
        self._add_index(story)
        self._add_executive_summary(story)
        self._add_methodology(story)
        self._add_tools(story)
        self._add_scanning_phase(story)
        self._add_bruteforce_phase(story)
        self._add_sqli_phase(story)
        self._add_credentials(story)
        self._add_risk_analysis(story)
        self._add_recommendations(story)
        self._add_conclusions(story)

        doc.build(story)
        print(f"   📄 ✅ REPORT GENERADO: {self.filename}")
