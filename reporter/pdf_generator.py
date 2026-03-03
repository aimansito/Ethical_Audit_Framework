from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.lib.colors import black, red, orange, yellow, green, white
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
        <b>Fecha:</b> {datetime.now().strftime('%Y-%m-%d %H:%M')}
        """, styles['Normal'])
        story.append(info)
        story.append(Spacer(1, 20))

        # PUERTOS
        if self.host.ports_open:
            port_data = [['Puerto', 'Servicio', 'Estado']]
            for port, info in list(self.host.ports_open.items())[:15]:
                port_data.append([str(port), info['service'][:30], info['state']])

            table = Table(port_data)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), black),
                ('TEXTCOLOR', (0, 0), (-1, 0), white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 1, black),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [yellow, green])
            ]))
            story.append(table)
            story.append(Spacer(1, 20))

        # VULNERABILIDADES
        risk_colors = {
            'CRITICAL': '#FF0000',
            'HIGH': '#FF8C00',
            'MEDIUM': '#FFD700',
            'LOW': '#228B22'
        }

        if self.host.vulnerabilities:
            story.append(Paragraph("VULNERABILIDADES CRÍTICAS", styles['Heading1']))
            for vuln in self.host.vulnerabilities:
                color_hex = risk_colors.get(vuln.risk.name, '#000000')
                story.append(Paragraph(
                    f"<font color='{color_hex}'>{vuln.name}</font>",
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
            story.append(Paragraph("No vulnerabilidades críticas detectadas", styles['Heading2']))

        # EVIDENCIA
        evidence = "Evidencia guardada en: outputs/"
        story.append(Paragraph(evidence, styles['Normal']))

        doc.build(story)
        print(f"   📄 ✅ REPORT GENERADO: {self.filename}")
