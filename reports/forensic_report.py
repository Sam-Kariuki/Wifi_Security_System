from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak
)

from pathlib import Path
from datetime import datetime


# ============================================================
# REPORT DIRECTORY
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

REPORT_DIRECTORY = BASE_DIR / "generated_reports"

REPORT_DIRECTORY.mkdir(
    exist_ok=True
)


# ============================================================
# REPORT GENERATION
# ============================================================

def generate_forensic_report(
    event,
    device,
    observations
):
    """
    Generate a PDF forensic report for one security event.
    """

    event_id = event[0]

    event_type = event[1]

    ip_address = event[2]

    mac_address = event[3]

    detection_timestamp = event[4]

    severity = event[5]

    description = event[6]

    status = event[7]

    classification = event[8]

    investigation_notes = event[9]

    resolution_notes = event[10]

    investigated_at = event[11]

    resolved_at = event[12]


    # --------------------------------------------------------
    # Device information
    # --------------------------------------------------------

    if device:

        device_id = device[0]

        device_ip = device[1]

        device_mac = device[2]

        hostname = device[3]

        device_status = device[4]

        first_seen = device[5]

        last_seen = device[6]

    else:

        device_id = "N/A"

        device_ip = ip_address

        device_mac = mac_address

        hostname = "N/A"

        device_status = "Unknown"

        first_seen = "N/A"

        last_seen = "N/A"


    # --------------------------------------------------------
    # File name
    # --------------------------------------------------------

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    filename = (
        f"forensic_event_{event_id}_{timestamp}.pdf"
    )

    report_path = REPORT_DIRECTORY / filename


    # ========================================================
    # DOCUMENT
    # ========================================================

    document = SimpleDocTemplate(
        str(report_path),
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm
    )


    # ========================================================
    # STYLES
    # ========================================================

    styles = getSampleStyleSheet()


    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontSize=20,
        spaceAfter=8
    )


    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        alignment=TA_CENTER,
        fontSize=10,
        textColor=colors.grey,
        spaceAfter=20
    )


    heading_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontSize=13,
        spaceBefore=12,
        spaceAfter=8
    )


    normal_style = ParagraphStyle(
        "ReportNormal",
        parent=styles["Normal"],
        fontSize=9,
        leading=13
    )


    small_style = ParagraphStyle(
        "SmallText",
        parent=styles["Normal"],
        fontSize=8,
        leading=11
    )


    # ========================================================
    # STORY
    # ========================================================

    story = []


    # ========================================================
    # TITLE
    # ========================================================

    story.append(
        Paragraph(
            "WI-FI SECURITY MONITORING",
            title_style
        )
    )


    story.append(
        Paragraph(
            "FORENSIC SECURITY EVENT REPORT",
            subtitle_style
        )
    )


    # ========================================================
    # REPORT METADATA
    # ========================================================

    story.append(
        Paragraph(
            "Report Information",
            heading_style
        )
    )


    report_information = [
        ["Report Generated", datetime.now().isoformat(
            timespec="seconds"
        )],
        ["Event ID", str(event_id)],
        ["Event Type", str(event_type)],
        ["Detection Time", str(detection_timestamp)],
        ["Severity", str(severity)],
        ["Status", str(status)],
        ["Classification", str(classification)]
    ]


    table = Table(
        report_information,
        colWidths=[50 * mm, 115 * mm]
    )


    table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (0, -1),
                colors.lightgrey
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.grey
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP"
            ),
            (
                "FONTNAME",
                (0, 0),
                (0, -1),
                "Helvetica-Bold"
            ),
            (
                "FONTSIZE",
                (0, 0),
                (-1, -1),
                9
            ),
            (
                "LEFTPADDING",
                (0, 0),
                (-1, -1),
                6
            ),
            (
                "RIGHTPADDING",
                (0, 0),
                (-1, -1),
                6
            ),
            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                6
            ),
            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                6
            )
        ])
    )


    story.append(table)

    story.append(Spacer(1, 8))


    # ========================================================
    # DEVICE INFORMATION
    # ========================================================

    story.append(
        Paragraph(
            "1. Detected Device Information",
            heading_style
        )
    )


    device_information = [
        ["Device ID", str(device_id)],
        ["IP Address", str(device_ip)],
        ["MAC Address", str(device_mac)],
        ["Hostname", str(hostname or "N/A")],
        ["Current Status", str(device_status)],
        ["First Seen", str(first_seen)],
        ["Last Seen", str(last_seen)]
    ]


    table = Table(
        device_information,
        colWidths=[50 * mm, 115 * mm]
    )


    table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (0, -1),
                colors.lightgrey
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.grey
            ),
            (
                "FONTNAME",
                (0, 0),
                (0, -1),
                "Helvetica-Bold"
            ),
            (
                "FONTSIZE",
                (0, 0),
                (-1, -1),
                9
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP"
            )
        ])
    )


    story.append(table)


    # ========================================================
    # ORIGINAL DETECTION
    # ========================================================

    story.append(
        Paragraph(
            "2. Original Detection Evidence",
            heading_style
        )
    )


    story.append(
        Paragraph(
            description or "No description recorded.",
            normal_style
        )
    )


    story.append(Spacer(1, 10))


    # ========================================================
    # INVESTIGATION
    # ========================================================

    story.append(
        Paragraph(
            "3. Investigation Information",
            heading_style
        )
    )


    investigation_information = [
        [
            "Investigation Started",
            str(investigated_at or "Not recorded")
        ],
        [
            "Classification",
            str(classification)
        ]
    ]


    table = Table(
        investigation_information,
        colWidths=[50 * mm, 115 * mm]
    )


    table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (0, -1),
                colors.lightgrey
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.grey
            ),
            (
                "FONTNAME",
                (0, 0),
                (0, -1),
                "Helvetica-Bold"
            ),
            (
                "FONTSIZE",
                (0, 0),
                (-1, -1),
                9
            )
        ])
    )


    story.append(table)

    story.append(Spacer(1, 8))


    story.append(
        Paragraph(
            "<b>Investigation Notes</b>",
            normal_style
        )
    )


    story.append(
        Paragraph(
            investigation_notes
            or "No investigation notes recorded.",
            normal_style
        )
    )


    # ========================================================
    # OBSERVATION HISTORY
    # ========================================================

    story.append(
        Paragraph(
            "4. Device Observation History",
            heading_style
        )
    )


    if observations:

        observation_data = [
            [
                "ID",
                "IP Address",
                "MAC Address",
                "Hostname",
                "Observed At"
            ]
        ]


        for observation in observations:

            observation_data.append([
                str(observation[0]),
                str(observation[1]),
                str(observation[2]),
                str(observation[3] or "N/A"),
                str(observation[4])
            ])


        table = Table(
            observation_data,
            colWidths=[
                12 * mm,
                30 * mm,
                38 * mm,
                35 * mm,
                42 * mm
            ],
            repeatRows=1
        )


        table.setStyle(
            TableStyle([
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.lightgrey
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.black
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold"
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.4,
                    colors.grey
                ),
                (
                    "FONTSIZE",
                    (0, 0),
                    (-1, -1),
                    7
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP"
                )
            ])
        )


        story.append(table)


    else:

        story.append(
            Paragraph(
                "No device observations are available.",
                normal_style
            )
        )


    # ========================================================
    # RESOLUTION
    # ========================================================

    story.append(
        Paragraph(
            "5. Resolution",
            heading_style
        )
    )


    resolution_information = [
        [
            "Final Status",
            str(status)
        ],
        [
            "Resolved At",
            str(resolved_at or "Not resolved")
        ]
    ]


    table = Table(
        resolution_information,
        colWidths=[50 * mm, 115 * mm]
    )


    table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (0, -1),
                colors.lightgrey
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.grey
            ),
            (
                "FONTNAME",
                (0, 0),
                (0, -1),
                "Helvetica-Bold"
            ),
            (
                "FONTSIZE",
                (0, 0),
                (-1, -1),
                9
            )
        ])
    )


    story.append(table)

    story.append(Spacer(1, 8))


    story.append(
        Paragraph(
            "<b>Resolution Notes</b>",
            normal_style
        )
    )


    story.append(
        Paragraph(
            resolution_notes
            or "No resolution notes recorded.",
            normal_style
        )
    )


    # ========================================================
    # FORENSIC INTEGRITY
    # ========================================================

    story.append(
        Paragraph(
            "6. Forensic Record Integrity",
            heading_style
        )
    )


    integrity_text = """
    This report is generated from records maintained by the
    Wi-Fi Security Monitoring and Forensic Analysis System.
    The original detection information, including the event
    type, network identifiers, detection timestamp, severity
    and original description, is preserved. Investigation,
    classification and resolution information represents
    subsequent analyst activity and is recorded separately.
    """


    story.append(
        Paragraph(
            integrity_text,
            normal_style
        )
    )


    # ========================================================
    # RESEARCH PROTOTYPE NOTICE
    # ========================================================

    story.append(Spacer(1, 15))


    story.append(
        Paragraph(
            "<b>Research Prototype</b>",
            normal_style
        )
    )


    story.append(
        Paragraph(
            "This report was generated by the Wi-Fi Security "
            "Monitoring and Forensic Analysis research prototype.",
            small_style
        )
    )


    # ========================================================
    # BUILD PDF
    # ========================================================

    document.build(story)


    return report_path