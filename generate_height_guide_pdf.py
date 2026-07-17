#!/usr/bin/env python3
"""Generate Height Growth Potential guide PDF."""

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

# Color palette
NAVY_DARK = colors.HexColor("#0f2744")
NAVY = colors.HexColor("#1a365d")
NAVY_LIGHT = colors.HexColor("#2c5282")
GREEN = colors.HexColor("#276749")
GREEN_LIGHT = colors.HexColor("#38a169")
GREEN_PALE = colors.HexColor("#e6f4ed")
SLATE = colors.HexColor("#4a5568")
SLATE_LIGHT = colors.HexColor("#718096")
WHITE = colors.white
BG_TINT = colors.HexColor("#f7fafc")
ACCENT_LINE = colors.HexColor("#68d391")

PAGE_W, PAGE_H = letter
MARGIN = 0.45 * inch


def draw_page_background(canvas, doc):
    canvas.saveState()
    # Top header band
    canvas.setFillColor(NAVY_DARK)
    canvas.rect(0, PAGE_H - 1.35 * inch, PAGE_W, 1.35 * inch, fill=1, stroke=0)
    # Accent stripe
    canvas.setFillColor(GREEN)
    canvas.rect(0, PAGE_H - 1.42 * inch, PAGE_W, 0.07 * inch, fill=1, stroke=0)
    # Subtle footer bar
    canvas.setFillColor(NAVY)
    canvas.rect(0, 0, PAGE_W, 0.22 * inch, fill=1, stroke=0)
    canvas.setFillColor(GREEN_LIGHT)
    canvas.rect(0, 0.22 * inch, PAGE_W, 0.03 * inch, fill=1, stroke=0)
    canvas.restoreState()


def build_styles():
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="DocTitle",
            fontName="Helvetica-Bold",
            fontSize=20,
            leading=24,
            textColor=WHITE,
            alignment=TA_CENTER,
            spaceAfter=4,
        )
    )
    styles.add(
        ParagraphStyle(
            name="DocSubtitle",
            fontName="Helvetica",
            fontSize=9.5,
            leading=12,
            textColor=colors.HexColor("#c6f6d5"),
            alignment=TA_CENTER,
            spaceAfter=0,
        )
    )
    styles.add(
        ParagraphStyle(
            name="SectionHeader",
            fontName="Helvetica-Bold",
            fontSize=11.5,
            leading=14,
            textColor=NAVY,
            spaceBefore=6,
            spaceAfter=5,
            leftIndent=0,
        )
    )
    styles.add(
        ParagraphStyle(
            name="EquipTitle",
            fontName="Helvetica-Bold",
            fontSize=9.5,
            leading=12,
            textColor=NAVY_DARK,
            spaceAfter=2,
        )
    )
    styles.add(
        ParagraphStyle(
            name="EquipBody",
            fontName="Helvetica",
            fontSize=8.2,
            leading=10.5,
            textColor=SLATE,
            spaceAfter=1,
        )
    )
    styles.add(
        ParagraphStyle(
            name="NutritionItem",
            fontName="Helvetica",
            fontSize=8.5,
            leading=11.5,
            textColor=SLATE,
            spaceAfter=4,
            leftIndent=6,
            bulletIndent=0,
        )
    )
    styles.add(
        ParagraphStyle(
            name="FooterNote",
            fontName="Helvetica-Oblique",
            fontSize=7,
            leading=9,
            textColor=SLATE_LIGHT,
            alignment=TA_CENTER,
        )
    )
    return styles


def equipment_card(title, details, help_text, styles):
    rows = [
        [Paragraph(f"<b>{title}</b>", styles["EquipTitle"])],
    ]
    for label, value in details:
        rows.append(
            [
                Paragraph(
                    f"<font color='#276749'><b>{label}:</b></font> {value}",
                    styles["EquipBody"],
                )
            ]
        )
    rows.append(
        [
            Paragraph(
                f"<font color='#1a365d'><b>How it helps:</b></font> {help_text}",
                styles["EquipBody"],
            )
        ]
    )
    card = Table(rows, colWidths=[2.35 * inch])
    card.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), BG_TINT),
                ("BOX", (0, 0), (-1, -1), 0.75, NAVY_LIGHT),
                ("LINEBELOW", (0, 0), (-1, 0), 2, GREEN),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    return card


def build_document(output_path):
    styles = build_styles()
    story = []

    # Title block (sits in header band area)
    story.append(Spacer(1, 0.15 * inch))
    story.append(Paragraph("Height Growth Potential", styles["DocTitle"]))
    story.append(
        Paragraph(
            "Equipment &amp; Nutrition Guide for Teens",
            styles["DocSubtitle"],
        )
    )
    story.append(
        Paragraph(
            "<i>Maximizing Natural Height Through Spinal Decompression &amp; HGH Stimulation</i>",
            styles["DocSubtitle"],
        )
    )
    story.append(Spacer(1, 0.22 * inch))

    # Section 1
    section1_header = Table(
        [[Paragraph("Section 1: Decompression Equipment (Safe &amp; Foldable)", styles["SectionHeader"])]],
        colWidths=[7.1 * inch],
    )
    section1_header.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), GREEN_PALE),
                ("LINEBEFORE", (0, 0), (0, -1), 4, GREEN),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    story.append(section1_header)
    story.append(Spacer(1, 0.08 * inch))

    equip1 = equipment_card(
        "ZENOVA Foldable Pull-Up Station",
        [
            ("Type", "Freestanding"),
            ("Floor Space", '52.4" L × 33.1" W (Folds to 14.6" L)'),
            ("Routine", "The Dead Hang (3 sets of 30–45 seconds)"),
        ],
        "Hanging straight down reverses daily gravity compression on spinal discs, "
        "allowing the spine to fully expand and maximizing standing postural height.",
        styles,
    )
    equip2 = equipment_card(
        "PRx Profile PRO Squat Rack",
        [
            ("Type", "Wall-Mounted (No floor drilling)"),
            ("Floor Space", '29.25" L × 53" W (Folds to 11.25" L)'),
            ("Routine", "Resistance Core &amp; Hangs"),
        ],
        "Supports heavy lifting to trigger natural spikes in <b>Human Growth Hormone (HGH)</b> "
        "and builds the core strength needed to prevent height-robbing slouching.",
        styles,
    )
    equip3 = equipment_card(
        "Teeter FitSpine X1 Inversion Table",
        [
            ("Type", "Freestanding"),
            ("Floor Space", '81.0" L × 28.8" W (Folds to 20.0" L)'),
            ("Routine", "Inverted Decompression (3–5 minutes at 30–60° angle)"),
        ],
        "Provides the deepest possible stretch to the spine and lower body joints, "
        "hydrating the spinal discs with fluid to maximize intervertebral space.",
        styles,
    )

    equip_row = Table([[equip1, equip2, equip3]], colWidths=[2.38 * inch, 2.38 * inch, 2.38 * inch])
    equip_row.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    story.append(equip_row)
    story.append(Spacer(1, 0.12 * inch))

    # Section 2
    section2_header = Table(
        [
            [
                Paragraph(
                    "Section 2: Essential Nutritional Support (The Building Blocks)",
                    styles["SectionHeader"],
                )
            ]
        ],
        colWidths=[7.1 * inch],
    )
    section2_header.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), GREEN_PALE),
                ("LINEBEFORE", (0, 0), (0, -1), 4, GREEN),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    story.append(section2_header)
    story.append(Spacer(1, 0.06 * inch))

    nutrition_items = [
        (
            "<b>High-Quality Protein</b>",
            "Influences <b>IGF-1</b>, the primary hormone for longitudinal bone growth. "
            "Eat lean meats, eggs, and dairy.",
        ),
        (
            "<b>Vitamin D3 + Calcium</b>",
            "Calcium builds bone, but the body needs <b>D3</b> to absorb it.",
        ),
        (
            "<b>Zinc</b>",
            "Mild zinc deficiency is clinically linked to stalled physical growth in teens.",
        ),
        (
            "<b>Sleep — The Ultimate Supplement</b>",
            "80% of natural <b>HGH</b> is released during deep sleep. "
            "<b>8 to 9 hours</b> is mandatory.",
        ),
    ]

    nutrition_cells = []
    for i in range(0, len(nutrition_items), 2):
        row = []
        for j in range(2):
            if i + j < len(nutrition_items):
                title, body = nutrition_items[i + j]
                cell_content = Table(
                    [
                        [Paragraph(title, styles["EquipTitle"])],
                        [Paragraph(body, styles["NutritionItem"])],
                    ],
                    colWidths=[3.45 * inch],
                )
                cell_content.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (-1, -1), WHITE),
                            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e0")),
                            ("LINEBEFORE", (0, 0), (0, -1), 3, GREEN_LIGHT),
                            ("TOPPADDING", (0, 0), (-1, -1), 6),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                            ("LEFTPADDING", (0, 0), (-1, -1), 8),
                            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                        ]
                    )
                )
                row.append(cell_content)
            else:
                row.append("")
        nutrition_cells.append(row)

    nutrition_table = Table(nutrition_cells, colWidths=[3.55 * inch, 3.55 * inch])
    nutrition_table.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(nutrition_table)
    story.append(Spacer(1, 0.1 * inch))

    disclaimer = Paragraph(
        "<i>Consult a healthcare provider before starting any new exercise or supplement routine. "
        "Genetics remain the primary factor in height potential.</i>",
        styles["FooterNote"],
    )
    story.append(disclaimer)

    frame = Frame(
        MARGIN,
        MARGIN + 0.15 * inch,
        PAGE_W - 2 * MARGIN,
        PAGE_H - 2 * MARGIN - 0.35 * inch,
        id="main",
        showBoundary=0,
    )
    doc = BaseDocTemplate(
        output_path,
        pagesize=letter,
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=MARGIN,
        bottomMargin=MARGIN,
    )
    doc.addPageTemplates([PageTemplate(id="main", frames=[frame], onPage=draw_page_background)])
    doc.build(story)
    print(f"PDF created: {output_path}")


if __name__ == "__main__":
    build_document("/workspace/Height_Growth_Potential_Guide.pdf")
