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

        # HEADER
        title = Paragraph("AUDITORÍA SEGURIDAD AUTOMATIZADA", styles['Title'])
        story.append(title)

        info = Paragraph(f"""
        <b>Objetivo:</b> {self.host.ip}<br/>
        <b>Riesgo:</b> <font color="red">{self.host.risk_level.value}</font><br/>
        <b>Fecha:</b> {datetime.now().strftime('%Y-%m-%d %H:%M')}<br/>
        <b>Vulnerabilidades:</b> {len(self.host.vulnerabilities)}<br/>
        <b>Credenciales extraídas:</b> {len(self.host.credentials)}
        """, styles['Normal'])
        story.append(info)
        story.append(Spacer(1, 20))

        # PUERTOS ABIERTOS
        if self.host.ports_open:
            story.append(Paragraph("PUERTOS Y SERVICIOS", styles['Heading1']))
            port_data = [['Puerto', 'Servicio', 'Versión', 'Estado']]
            for port, info in list(self.host.ports_open.items())[:15]:
                port_data.append([
                    str(port),
                    info['service'][:25],
                    info.get('version', '')[:20],
                    info['state']
                ])

            table = Table(port_data, colWidths=[60, 120, 120, 60])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), black),
                ('TEXTCOLOR', (0, 0), (-1, 0), white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 1, black),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [HexColor('#f5f5f5'), white])
            ]))
            story.append(table)
            story.append(Spacer(1, 20))

        # CREDENCIALES EXTRAÍDAS
        if self.host.credentials:
            story.append(Paragraph("CREDENCIALES EXTRAÍDAS", styles['Heading1']))
            story.append(Paragraph(
                "<font color='red'><b>ALERTA:</b> Se han extraído credenciales del sistema objetivo.</font>",
                styles['Normal']
            ))
            story.append(Spacer(1, 8))

            cred_data = [['Fuente', 'Usuario', 'Contraseña/Hash']]
            for cred in self.host.credentials:
                cred_data.append([
                    cred.get('source', 'N/A'),
                    cred.get('user', 'N/A'),
                    cred.get('password', 'N/A')[:40]
                ])

            cred_table = Table(cred_data, colWidths=[120, 100, 200])
            cred_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), red),
                ('TEXTCOLOR', (0, 0), (-1, 0), white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 1, black),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [HexColor('#fff0f0'), white])
            ]))
            story.append(cred_table)
            story.append(Spacer(1, 20))

        # VULNERABILIDADES
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
                    f"<font color='{color_hex}'>[{vuln.risk.name}]</font> {vuln.name}",
                    styles['Heading2']
                ))
                story.append(Paragraph(vuln.description, styles['Normal']))
                if vuln.recommendations:
                    story.append(Paragraph(
                        f"<i>Recomendación: {vuln.recommendations}</i>",
                        styles['Italic']
                    ))
                story.append(Spacer(1, 12))
        else:
            story.append(Paragraph("No se detectaron vulnerabilidades", styles['Heading2']))

        # RECOMENDACIONES GENERALES
        story.append(Paragraph("RECOMENDACIONES GENERALES", styles['Heading1']))
        recs = [
            "1. Actualizar WordPress y todos los plugins a la última versión",
            "2. Configurar DVWA con security=impossible en producción",
            "3. Implementar contraseñas robustas y autenticación 2FA",
            "4. Configurar un WAF (Web Application Firewall)",
            "5. Restringir acceso a MySQL solo desde localhost",
            "6. Deshabilitar XML-RPC en WordPress",
            "7. Implementar prepared statements en todas las consultas SQL"
        ]
        for rec in recs:
            story.append(Paragraph(rec, styles['Normal']))
        story.append(Spacer(1, 8))

        # EVIDENCIA
        story.append(Spacer(1, 12))
        story.append(Paragraph("Evidencia completa guardada en: outputs/", styles['Normal']))

        doc.build(story)
        print(f"   📄 ✅ REPORT GENERADO: {self.filename}")
