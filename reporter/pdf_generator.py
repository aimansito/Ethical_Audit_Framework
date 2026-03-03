from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.lib.colors import black, red, orange, yellow, green, white, HexColor
from datetime import datetime
from pathlib import Path
from models.host import Host


class PDFReportGenerator:
    def __init__(self, host: Host):
        self.host = host
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.filename = Path(f"outputs/REPORT_{host.ip.replace('.','_')}_{self.timestamp}.pdf")

    def generate(self):
        doc = SimpleDocTemplate(str(self.filename), pagesize=A4)
        styles = getSampleStyleSheet()
        story = []

        # ── HEADER ──
        title = Paragraph("INFORME DE AUDITORÍA DE SEGURIDAD", styles['Title'])
        story.append(title)

        info = Paragraph(f"""
        <b>Objetivo:</b> {self.host.ip}<br/>
        <b>Riesgo Global:</b> <font color="red">{self.host.risk_level.value}</font><br/>
        <b>Fecha:</b> {datetime.now().strftime('%Y-%m-%d %H:%M')}<br/>
        <b>Puertos abiertos:</b> {len(self.host.ports_open)}<br/>
        <b>Vulnerabilidades:</b> {len(self.host.vulnerabilities)}<br/>
        <b>Credenciales extraídas:</b> {len(self.host.credentials)}<br/>
        <b>Directorios descubiertos:</b> {len(getattr(self.host, 'directories', []))}
        """, styles['Normal'])
        story.append(info)
        story.append(Spacer(1, 20))

        # ── PUERTOS ABIERTOS ──
        if self.host.ports_open:
            story.append(Paragraph("PUERTOS Y SERVICIOS DETECTADOS", styles['Heading1']))
            port_data = [['Puerto', 'Servicio', 'Versión', 'Estado']]
            for port, info in sorted(self.host.ports_open.items()):
                ver = f"{info.get('product','')} {info.get('version','')}".strip()
                port_data.append([
                    f"{port}/tcp",
                    info['service'][:25],
                    ver[:30],
                    info['state']
                ])

            table = Table(port_data, colWidths=[60, 100, 160, 60])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), HexColor('#1a1a2e')),
                ('TEXTCOLOR', (0, 0), (-1, 0), white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, black),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [HexColor('#f0f0f0'), white])
            ]))
            story.append(table)
            story.append(Spacer(1, 15))

        # ── DIRECTORIOS DESCUBIERTOS ──
        dirs = getattr(self.host, 'directories', [])
        if dirs:
            story.append(Paragraph("DIRECTORIOS DESCUBIERTOS (Gobuster)", styles['Heading1']))
            dir_data = [['Directorio', 'Status']]
            for d in dirs[:20]:
                dir_data.append([d.get('path', ''), d.get('status', '')])

            dir_table = Table(dir_data, colWidths=[300, 80])
            dir_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), HexColor('#16213e')),
                ('TEXTCOLOR', (0, 0), (-1, 0), white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, black),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [HexColor('#f8f8ff'), white])
            ]))
            story.append(dir_table)
            story.append(Spacer(1, 15))

        # ── CREDENCIALES EXTRAÍDAS ──
        if self.host.credentials:
            story.append(Paragraph("CREDENCIALES EXTRAÍDAS", styles['Heading1']))
            story.append(Paragraph(
                "<font color='red'><b>⚠ ALERTA CRÍTICA:</b> Se han extraído credenciales del sistema.</font>",
                styles['Normal']
            ))
            story.append(Spacer(1, 8))

            cred_data = [['Fuente', 'Usuario', 'Contraseña/Hash', 'Crackeado']]
            for cred in self.host.credentials:
                cracked = '✅ SÍ' if cred.get('cracked') else '❌ NO'
                cred_data.append([
                    cred.get('source', 'N/A')[:20],
                    cred.get('user', 'N/A'),
                    cred.get('password', 'N/A')[:35],
                    cracked
                ])

            cred_table = Table(cred_data, colWidths=[100, 80, 170, 60])
            cred_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), red),
                ('TEXTCOLOR', (0, 0), (-1, 0), white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, black),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [HexColor('#fff0f0'), white])
            ]))
            story.append(cred_table)
            story.append(Spacer(1, 15))

        # ── VULNERABILIDADES ──
        risk_colors = {
            'CRITICAL': '#FF0000',
            'HIGH': '#FF8C00',
            'MEDIUM': '#FFD700',
            'LOW': '#228B22'
        }

        if self.host.vulnerabilities:
            story.append(Paragraph("VULNERABILIDADES DETECTADAS", styles['Heading1']))
            for vuln in self.host.vulnerabilities:
                color_hex = risk_colors.get(vuln.risk.name, '#000000')
                story.append(Paragraph(
                    f"<font color='{color_hex}'><b>[{vuln.risk.name}]</b></font> {vuln.name}",
                    styles['Heading3']
                ))
                story.append(Paragraph(vuln.description, styles['Normal']))
                if vuln.recommendations:
                    story.append(Paragraph(
                        f"<i>📋 Recomendación: {vuln.recommendations}</i>",
                        styles['Italic']
                    ))
                story.append(Spacer(1, 10))
        else:
            story.append(Paragraph("No se detectaron vulnerabilidades", styles['Heading2']))

        # ── RECOMENDACIONES ──
        story.append(Paragraph("RECOMENDACIONES DE SEGURIDAD", styles['Heading1']))
        recs = [
            "1. Actualizar WordPress y plugins a la última versión estable",
            "2. Configurar DVWA security=impossible en producción",
            "3. Implementar contraseñas robustas (mín. 12 caracteres, especiales)",
            "4. Activar autenticación 2FA en WordPress y paneles admin",
            "5. Configurar WAF (Web Application Firewall) - ModSecurity",
            "6. Restringir MySQL: solo conexiones desde localhost",
            "7. Deshabilitar XML-RPC en WordPress",
            "8. Usar prepared statements en TODAS las consultas SQL",
            "9. Implementar rate-limiting en formularios de login",
            "10. Auditorías periódicas y monitoreo de logs"
        ]
        for rec in recs:
            story.append(Paragraph(rec, styles['Normal']))

        story.append(Spacer(1, 15))
        story.append(Paragraph(
            f"<i>Evidencia completa en: outputs/ | Generado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i>",
            styles['Normal']
        ))

        doc.build(story)
        print(f"   📄 ✅ REPORT GENERADO: {self.filename}")
